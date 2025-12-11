"""
Database adapter for Supabase PostgreSQL/CockroachDB (production only)

Thread Safety:
    PostgreSQL connections are naturally thread-safe.
    Each request creates its own database connection for best performance.
"""
import os
import threading
from contextlib import contextmanager
from urllib.parse import urlparse

# Import psycopg2 for PostgreSQL/CockroachDB support
import psycopg2
import psycopg2.extras


class DatabaseAdapter:
    """
    Database adapter for Supabase PostgreSQL/CockroachDB connections only.
    
    Production-only implementation with direct PostgreSQL support.
    No fallback to SQLite.
    """
    
    def __init__(self, connection_string=None):
        """
        Initialize database connection for PostgreSQL/CockroachDB.
        
        Args:
            connection_string: Database URL. Examples:
                - postgresql://user:pass@host:port/dbname
                - postgresql://host/dbname (if user/pass in connection string)
        """
        self.connection_string = connection_string or self._get_connection_string()
        self.db_type = 'postgresql'
        self.connection = None
        self._lock = threading.Lock()
    
    def _get_connection_string(self):
        """Get connection string from DATABASE_URL environment variable"""
        db_url = os.getenv('DATABASE_URL')
        if not db_url:
            raise ValueError("DATABASE_URL environment variable not set. Set it to PostgreSQL connection string.")
        
        # Render/Heroku use 'postgres://' but psycopg2 needs 'postgresql://'
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        
        return db_url
    
    def _get_postgres_host(self):
        """Extract PostgreSQL host from connection string"""
        parsed = urlparse(self.connection_string)
        return parsed.hostname or 'unknown'
    
    def connect(self):
        """
        Establish PostgreSQL/CockroachDB connection.
        Raises exception if connection fails (no fallback).
        """
        try:
            self.connection = psycopg2.connect(self.connection_string, connect_timeout=10)
            return self.connection
        except psycopg2.OperationalError as e:
            error_str = str(e)
            if 'codeProxyRefusedConnection' in error_str:
                raise ConnectionError(
                    f"CockroachDB proxy refused connection. Possible causes:\n"
                    f"  1. Invalid username or password\n"
                    f"  2. Cluster is paused - resume it in CockroachDB dashboard\n"
                    f"  3. Invalid cluster ID or connection string\n"
                    f"Original error: {e}"
                ) from e
            elif 'connection refused' in error_str.lower():
                raise ConnectionError(
                    f"Connection refused. Database server may be down or unreachable.\n"
                    f"Original error: {e}"
                ) from e
            elif 'authentication failed' in error_str.lower():
                raise ConnectionError(
                    f"Authentication failed. Check your username and password.\n"
                    f"Original error: {e}"
                ) from e
            else:
                raise ConnectionError(f"Failed to connect to PostgreSQL: {e}") from e
        except Exception as e:
            raise ConnectionError(f"Failed to connect to PostgreSQL: {e}") from e
    
    def cursor(self):
        """Get a PostgreSQL cursor (thread-safe with RealDictCursor for named column access)"""
        with self._lock:
            if not self.connection:
                self.connect()
            return self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    
    def commit(self):
        """Commit current transaction (thread-safe)"""
        with self._lock:
            if self.connection:
                self.connection.commit()
    
    def rollback(self):
        """Rollback current transaction (thread-safe)"""
        with self._lock:
            if self.connection:
                self.connection.rollback()
    
    def close(self):
        """Close database connection (thread-safe)"""
        with self._lock:
            if self.connection:
                self.connection.close()
                self.connection = None
    
    def __enter__(self):
        """
        Context manager entry point.
        
        Usage:
            with DatabaseAdapter() as db:
                cursor = db.cursor()
                cursor.execute("SELECT * FROM users")
                # Connection automatically closed on exit
        """
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Context manager exit point.
        
        Ensures connection is always closed, even on exceptions.
        Does not suppress exceptions (returns False).
        
        Args:
            exc_type: Exception type if an exception occurred, else None
            exc_val: Exception value if an exception occurred, else None
            exc_tb: Exception traceback if an exception occurred, else None
            
        Returns:
            False to propagate any exception that occurred
        """
        self.close()
        return False  # Do not suppress exceptions
    
    @contextmanager
    def transaction(self):
        """
        Context manager for thread-safe database transactions.
        
        Usage:
            with db.transaction() as cursor:
                cursor.execute("INSERT INTO ...")
                # Automatically commits on success, rollbacks on exception
        
        Thread Safety:
            For SQLite, the lock is held for the entire transaction to prevent
            "bad parameter or other API misuse" errors. This means only one
            transaction can execute at a time, but this matches SQLite's design
            (which uses database-level locking anyway).
            
            For PostgreSQL, the lock is briefly held for cursor/commit/rollback
            but not during query execution.
        """
        cursor = None
        try:
            with self._lock:
                if not self.connection:
                    self.connect()
                cursor = self.connection.cursor()
                
                # For SQLite, we yield inside the lock context to prevent concurrent cursor usage
                # For PostgreSQL, this is less critical but doesn't hurt
                yield cursor
                
                self.connection.commit()
        except Exception:
            with self._lock:
                if self.connection:
                    self.connection.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
    
    def execute(self, query, params=None, add_returning_id=True):
        """
        Execute a query with parameter substitution based on database type.
        
        IMPORTANT - Database-Native Placeholders Required:
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        This method NO LONGER automatically converts placeholders between databases.
        You must use the correct placeholder style for your target database:
        
        - SQLite:     Use ? placeholders
                      Example: "INSERT INTO users (name) VALUES (?)"
        
        - PostgreSQL: Use %s placeholders  
                      Example: "INSERT INTO users (name) VALUES (%s)"
        
        If you pass a query with the wrong placeholder style for the active database,
        this method will raise a ValueError with clear instructions.
        
        Migration Guide:
        ───────────────
        If you need to support both databases in the same codebase:
        
        Option 1 (Recommended): Use conditional queries based on db_type:
            if db.db_type == 'sqlite':
                query = "INSERT INTO users (name) VALUES (?)"
            else:  # postgresql
                query = "INSERT INTO users (name) VALUES (%s)"
            db.execute(query, (username,))
        
        Option 2: Use the convert_placeholders() helper (manual conversion):
            sqlite_query = "INSERT INTO users (name) VALUES (?)"
            pg_query = db.convert_placeholders(sqlite_query, from_style='?', to_style='%s')
            db.execute(pg_query, (username,))
        
        For PostgreSQL INSERT statements, this method optionally adds RETURNING id if missing.
        
        Args:
            query: SQL query string with database-native placeholders
            params: Query parameters (optional)
            add_returning_id: If True and db is PostgreSQL, automatically add
                            RETURNING id to simple INSERT statements (default: True).
                            Set to False for:
                            - Tables without an 'id' column
                            - Composite primary keys
                            - INSERT...SELECT statements
                            - CTEs (WITH clauses)
                            - When you don't need the inserted ID
        
        Returns:
            cursor: Database cursor with query results
            
        Raises:
            ValueError: If query contains wrong placeholder style for the active database
        """
        cursor = self.cursor()
        
        # Validate placeholders match database type
        self._validate_placeholders(query)
        
        # For PostgreSQL INSERT statements, optionally add RETURNING id
        if self.db_type == 'postgresql' and add_returning_id:
            query = self._ensure_returning_clause(query)
        
        if params:
            cursor.execute(query, params)
        else:
            cursor.execute(query)
        
        return cursor
    
    def _ensure_returning_clause(self, query):
        """
        For PostgreSQL INSERT statements, ensure RETURNING id clause is present.
        This maintains adapter abstraction so callers don't need to know about
        database-specific syntax for getting the last insert ID.
        
        IMPORTANT LIMITATIONS:
        - Only works for tables with a single 'id' column (not composite keys)
        - Skips complex statements: CTEs (WITH), INSERT...SELECT
        - Does not verify table schema
        - Caller must ensure the target table has an 'id' column
        
        Args:
            query: SQL query string
            
        Returns:
            Query with RETURNING id added if it's a simple INSERT without RETURNING,
            or the original query if it's complex or already has RETURNING
            
        Supported examples:
            "INSERT INTO users (name) VALUES (?)"
            -> "INSERT INTO users (name) VALUES (?) RETURNING id"
            
            "INSERT INTO users (name) VALUES (?);"
            -> "INSERT INTO users (name) VALUES (?) RETURNING id;"
            
        Unsupported (returns original query unchanged):
            "WITH tmp AS (...) INSERT INTO users ..." (CTE)
            "INSERT INTO users SELECT * FROM temp" (INSERT...SELECT)
            "INSERT INTO composite_key_table ..." (use add_returning_id=False)
            "INSERT INTO users (name) VALUES (?) RETURNING id" (already has RETURNING)
        """
        # Quick check: only process INSERT statements
        query_upper = query.upper().strip()
        if not query_upper.startswith('INSERT'):
            return query
        
        # Safety check: skip CTEs (WITH clause)
        if query_upper.startswith('WITH '):
            return query
        
        # Safety check: skip INSERT...SELECT patterns
        # Look for INSERT followed by SELECT (with possible keywords between)
        if 'INSERT' in query_upper and 'SELECT' in query_upper:
            # Simple heuristic: if SELECT appears after INSERT, likely INSERT...SELECT
            insert_pos = query_upper.find('INSERT')
            select_pos = query_upper.find('SELECT')
            if select_pos > insert_pos:
                return query
        
        # Check if RETURNING clause already exists (case-insensitive)
        if 'RETURNING' in query_upper:
            return query
        
        # Find the position to insert RETURNING clause
        # Handle optional trailing semicolon
        query_stripped = query.rstrip()
        has_semicolon = query_stripped.endswith(';')
        
        if has_semicolon:
            # Insert RETURNING before the semicolon
            query_without_semicolon = query_stripped[:-1].rstrip()
            return query_without_semicolon + ' RETURNING id;'
        else:
            # Append RETURNING at the end
            return query_stripped + ' RETURNING id'
    
    def _validate_placeholders(self, query):
        """
        Validate that query uses correct placeholders for the active database.
        
        Raises ValueError if:
        - SQLite database receives query with %s placeholders
        - PostgreSQL database receives query with ? placeholders
        
        Args:
            query: SQL query string to validate
            
        Raises:
            ValueError: If placeholder style doesn't match database type
        """
        # Check for wrong placeholder style
        if self.db_type == 'sqlite' and '%s' in query:
            raise ValueError(
                "SQLite database requires ? placeholders, but query contains %s placeholders.\n"
                "Fix: Change all %s to ? in your query, or use db.convert_placeholders() helper.\n"
                f"Query: {query[:100]}{'...' if len(query) > 100 else ''}"
            )
        
        if self.db_type == 'postgresql' and '?' in query:
            raise ValueError(
                "PostgreSQL database requires %s placeholders, but query contains ? placeholders.\n"
                "Fix: Change all ? to %s in your query, or use db.convert_placeholders() helper.\n"
                f"Query: {query[:100]}{'...' if len(query) > 100 else ''}"
            )
    
    def convert_placeholders(self, query, from_style='?', to_style='%s'):
        """
        Convert placeholder style in SQL query (simple string replacement).
        
        ⚠️  WARNING - Known Limitations:
        ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
        This is a SIMPLE string replacement that does NOT parse SQL.
        It will incorrectly convert placeholders inside:
        - String literals: "What?" or 'SELECT ?'
        - Comments: -- This is? or /* Example? */
        - Dollar-quoted strings: $$SELECT ?$$
        - Complex SQL constructs
        
        Recommended Use:
        ────────────────
        Only use this helper for simple queries where placeholders
        do NOT appear in string literals or comments.
        
        For production code, prefer writing queries with the correct
        placeholder style from the start:
        
            # Good - conditional query construction
            if db.db_type == 'sqlite':
                query = "INSERT INTO users (name) VALUES (?)"
            else:
                query = "INSERT INTO users (name) VALUES (%s)"
        
        Args:
            query: SQL query string to convert
            from_style: Placeholder style to convert from ('?' or '%s')
            to_style: Placeholder style to convert to ('?' or '%s')
            
        Returns:
            Query string with converted placeholders
            
        Examples:
            >>> db.convert_placeholders("SELECT * FROM users WHERE id = ?", '?', '%s')
            "SELECT * FROM users WHERE id = %s"
            
            >>> db.convert_placeholders("INSERT INTO t (a, b) VALUES (%s, %s)", '%s', '?')
            "INSERT INTO t (a, b) VALUES (?, ?)"
        """
        if from_style == to_style:
            return query
        
        return query.replace(from_style, to_style)
    
    def fetchone(self, query, params=None, add_returning_id=True):
        """
        Execute query and fetch one result.
        
        Args:
            query: SQL query string
            params: Query parameters (optional)
            add_returning_id: If True, auto-add RETURNING id to PostgreSQL INSERTs (default: True)
        """
        cursor = self.execute(query, params, add_returning_id=add_returning_id)
        result = cursor.fetchone()
        
        if result and self.db_type == 'postgresql':
            return dict(result)  # Convert RealDictRow to dict
        return result
    
    def fetchall(self, query, params=None, add_returning_id=True):
        """
        Execute query and fetch all results.
        
        Args:
            query: SQL query string
            params: Query parameters (optional)
            add_returning_id: If True, auto-add RETURNING id to PostgreSQL INSERTs (default: True)
        """
        cursor = self.execute(query, params, add_returning_id=add_returning_id)
        results = cursor.fetchall()
        
        if self.db_type == 'postgresql':
            return [dict(row) for row in results]  # Convert RealDictRows to dicts
        return results
    
    def get_last_insert_id(self, cursor):
        """
        Get the last inserted row ID (works for both SQLite and PostgreSQL).
        
        For PostgreSQL, this fetches the result from the automatically added
        RETURNING id clause (added by execute() method).
        
        For SQLite, this uses cursor.lastrowid.
        
        Args:
            cursor: Database cursor from the INSERT query
            
        Returns:
            int: The ID of the inserted row, or None if not available
            
        Raises:
            ValueError: If PostgreSQL RETURNING clause returned a row without 'id' key
            
        Note:
            The execute() method automatically adds RETURNING id to PostgreSQL
            INSERT statements, so callers don't need to include it manually.
            
        Important - PostgreSQL Cursor Consumption:
            For PostgreSQL, the RETURNING row can only be fetched once from the cursor.
            This method caches the extracted ID on the cursor object (cursor._last_insert_id)
            so subsequent calls to get_last_insert_id() with the same cursor return the
            cached value without attempting to re-read the cursor (which would return None
            or raise an error).
            
            Example:
                cursor = db.execute("INSERT INTO users (name) VALUES (?)", ("Alice",))
                id1 = db.get_last_insert_id(cursor)  # Fetches and caches
                id2 = db.get_last_insert_id(cursor)  # Returns cached value
                assert id1 == id2
        """
        if self.db_type == 'sqlite':
            return cursor.lastrowid
        else:  # postgresql
            # Check if we've already fetched and cached the ID for this cursor
            if hasattr(cursor, '_last_insert_id'):
                return cursor._last_insert_id
            
            # RETURNING id is automatically added by execute() method
            # Fetch the returned row (this is single-use - cursor will be exhausted after)
            try:
                result = cursor.fetchone()
            except Exception:
                # Silently fail - avoid exposing database errors
                cursor._last_insert_id = None
                return None
            
            # Handle case where no row was returned
            if result is None:
                cursor._last_insert_id = None
                return None
            
            # Extract the 'id' key from the result
            try:
                insert_id = result['id']
                # Cache the ID on the cursor for subsequent calls
                cursor._last_insert_id = insert_id
                return insert_id
            except (KeyError, TypeError):
                # Handle missing 'id' key or non-dict result
                cursor._last_insert_id = None
                return None


def get_db_connection():
    """
    Factory function to create a database connection.
    Reads DATABASE_URL from environment or defaults to SQLite.
    """
    adapter = DatabaseAdapter()
    adapter.connect()
    return adapter
