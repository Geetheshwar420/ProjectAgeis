# Messaging App - Production Setup (Supabase PostgreSQL Only)

## Overview

This is a quantum-encrypted secure messaging application using Supabase PostgreSQL/CockroachDB as the production database. All SQLite fallback mechanisms and development databases have been removed for production cleanliness.

## Architecture

- **Frontend**: React.js (Vercel deployment ready)
- **Backend**: Flask with SocketIO
- **Database**: Supabase PostgreSQL/CockroachDB
- **Encryption**: Post-quantum cryptography (Kyber, Dilithium, BB84)

## Quick Start

### 1. Environment Setup

Create `.env` file in `backend/` directory:

```bash
DATABASE_URL=postgresql://user:password@host:port/database?sslmode=require
SECRET_KEY=your_secret_key_here
FLASK_ENV=production
```

### 2. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 3. Initialize Database

```bash
python db_init.py
```

This will create all required tables in Supabase PostgreSQL.

### 4. Run Backend Server

```bash
python run.py
```

Server will be available at `http://localhost:5000`

### 5. Run Frontend

```bash
cd frontend
npm install
npm start
```

Frontend will be available at `http://localhost:3000`

## Database Schema

The application uses the following tables in PostgreSQL:

### users
- `id` (SERIAL PRIMARY KEY)
- `username` (TEXT UNIQUE)
- `password_hash` (TEXT)
- `email` (TEXT UNIQUE)
- `created_at` (TIMESTAMP)
- `kyber_public_key` (TEXT) - Kyber KEM public key
- `kyber_secret_key` (TEXT) - Kyber KEM secret key
- `dilithium_public_key` (TEXT) - Dilithium signature public key
- `dilithium_secret_key` (TEXT) - Dilithium signature secret key

### messages
- `id` (SERIAL PRIMARY KEY)
- `sender_id` (TEXT) - Sender username
- `recipient_id` (TEXT) - Recipient username
- `encrypted_message` (TEXT) - AES-256-GCM encrypted content
- `signature` (TEXT) - Dilithium signature
- `nonce` (TEXT) - Encryption nonce
- `tag` (TEXT) - GCM authentication tag
- `session_id` (TEXT) - Session key ID
- `timestamp` (TIMESTAMP)
- `formatted_timestamp` (TEXT)
- `iso_timestamp` (TEXT)
- `status` (TEXT) - 'sent', 'delivered', 'read'
- `delivered_at` (TIMESTAMP)
- `read_at` (TIMESTAMP)

### friend_requests
- `id` (SERIAL PRIMARY KEY)
- `requester` (TEXT) - Requester username
- `recipient` (TEXT) - Recipient username
- `status` (TEXT) - 'pending', 'accepted', 'rejected'
- `created_at` (TIMESTAMP)

### session_keys
- `id` (SERIAL PRIMARY KEY)
- `session_id` (TEXT UNIQUE) - Session identifier
- `user_a` (TEXT) - First user
- `user_b` (TEXT) - Second user
- `session_key` (TEXT) - Shared session key
- `bb84_key` (TEXT) - BB84 quantum key
- `kyber_shared_secret` (TEXT) - Kyber KEM shared secret
- `created_at` (TIMESTAMP)
- `expires_at` (TIMESTAMP)
- `status` (TEXT) - 'active', 'expired'

## Key Features

### Security
- **Post-Quantum Cryptography**: Kyber KEM for key encapsulation, Dilithium for signatures
- **Quantum Key Distribution**: BB84 protocol for quantum-secure session keys
- **End-to-End Encryption**: AES-256-GCM message encryption
- **Perfect Forward Secrecy**: Session-based key rotation

### Performance
- **Optimized Crypto**: Precomputed twiddle factors, cached operations
- **Efficient Database**: Indexed queries for fast lookups
- **Connection Pooling**: Thread-safe database access

### Reliability
- **Production Database**: Enterprise-grade Supabase PostgreSQL
- **Automatic Indexes**: Performance optimization built-in
- **Error Handling**: Comprehensive exception handling

## File Structure

```
backend/
├── app.py              # Flask application entry point
├── run.py              # WSGI server runner
├── db_adapter.py       # PostgreSQL connection adapter
├── db_init.py          # Database schema initialization
├── db_models.py        # Database models and ORM
├── config.py           # Application configuration
├── utils.py            # Utility functions
├── .env                # Environment variables
├── requirements.txt    # Python dependencies
├── supabase_schema.sql # Supabase SQL schema
├── crypto/             # Cryptographic modules
│   ├── kyber.py       # Kyber KEM implementation
│   ├── dilithium.py   # Dilithium signature implementation
│   ├── bb84.py        # BB84 quantum protocol
│   └── quantum_service.py # Unified crypto service
├── certs/             # SSL certificates
└── uploads/           # User file uploads

frontend/
├── src/               # React source code
├── public/            # Static assets
└── package.json       # Dependencies
```

## Deployment

### Supabase Setup

1. Create a Supabase project at https://supabase.com
2. Run `backend/supabase_schema.sql` in the SQL editor
3. Copy connection string to `.env` as `DATABASE_URL`

### Backend Deployment (Render/Railway)

```bash
python run.py
```

**Environment Variables**:
- `DATABASE_URL`: Supabase PostgreSQL connection string
- `SECRET_KEY`: Flask session secret key
- `FLASK_ENV`: Set to 'production'

### Frontend Deployment (Vercel)

See `frontend/vercel.json` for Vercel configuration.

## Troubleshooting

### PostgreSQL Connection Failed

**Error**: `connection refused`

**Solution**:
1. Verify DATABASE_URL is correct
2. Check Supabase project status at https://app.supabase.com
3. Verify IP whitelisting allows your connection
4. Test connection: `psql "postgresql://..."`

### Table Does Not Exist

**Error**: `relation "users" does not exist`

**Solution**:
Run database initialization:
```bash
python db_init.py
```

### SSL Certificate Error

**Error**: `SSL: CERTIFICATE_VERIFY_FAILED`

**Solution**:
Ensure DATABASE_URL uses `sslmode=require`

## Testing

Run the smoke tests:

```bash
python smoke_test.py
```

## Production Checklist

- [ ] DATABASE_URL set in environment
- [ ] Database tables created (`python db_init.py`)
- [ ] HTTPS enabled on frontend
- [ ] SSL certificates installed
- [ ] Environment variables set for production
- [ ] Logging configured
- [ ] Monitoring/alerting enabled
- [ ] Backup strategy in place
- [ ] Load testing completed

## API Endpoints

See `docs/DEPLOYMENT_GUIDE.md` for complete API documentation.

## Security Notes

- Never commit `.env` files
- Use strong SECRET_KEY for session encryption
- Rotate DATABASE_URL credentials regularly
- Enable PostgreSQL encryption at rest
- Use HTTPS in production
- Monitor database access logs

## Contributing

1. Create feature branch
2. Test locally with `pytest`
3. Ensure PostgreSQL compatibility
4. Submit pull request

## License

MIT

## Support

For issues:
1. Check Supabase status page
2. Review logs with `python run.py 2>&1 | head -50`
3. Verify DATABASE_URL configuration
4. Check database tables exist

---

**Status**: Production-Ready ✅  
**Database**: Supabase PostgreSQL Only  
**Last Updated**: December 11, 2025
