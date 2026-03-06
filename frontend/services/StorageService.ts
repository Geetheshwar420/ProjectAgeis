/**
 * StorageService.ts
 * Manages local persistence for messages and cryptographic keys using IndexedDB.
 * Ensures data is wiped on logout.
 */

const DB_NAME = 'AgesSecureChat';
const DB_VERSION = 1;
const STORE_NAME = 'messages';
const KEY_STORE_NAME = 'identity_keys';

export interface LocalMessage {
    id: string;
    sender_id: string;
    sender_username: string;
    recipient_id: string;
    content: string;
    type: 'text' | 'file' | 'image';
    url?: string;
    timestamp: string;
    is_encrypted: boolean;
}

export interface IdentityKeys {
    kyberPubKey: string;
    kyberSecKey: string;
    dilithiumPubKey: string;
    dilithiumSecKey: string;
}

export class StorageService {
    private static db: IDBDatabase | null = null;

    private static async getDB(): Promise<IDBDatabase> {
        if (this.db) return this.db;

        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION + 1); // Increment version if needed or handle upgrade

            request.onupgradeneeded = (event) => {
                const db = (event.target as IDBOpenDBRequest).result;
                if (!db.objectStoreNames.contains(STORE_NAME)) {
                    db.createObjectStore(STORE_NAME, { keyPath: 'id' });
                }
                if (!db.objectStoreNames.contains(KEY_STORE_NAME)) {
                    db.createObjectStore(KEY_STORE_NAME); // Single entry store
                }
            };

            request.onsuccess = (event) => {
                this.db = (event.target as IDBOpenDBRequest).result;
                resolve(this.db!);
            };

            request.onerror = (event) => {
                reject('Failed to open IndexedDB');
            };
        });
    }

    /**
     * Save identity keys locally
     */
    public static async saveIdentityKeys(keys: IdentityKeys): Promise<void> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(KEY_STORE_NAME, 'readwrite');
            const store = transaction.objectStore(KEY_STORE_NAME);
            const request = store.put(keys, 'my_keys');

            request.onsuccess = () => resolve();
            request.onerror = () => reject('Failed to save identity keys');
        });
    }

    /**
     * Get identity keys from local storage
     */
    public static async getIdentityKeys(): Promise<IdentityKeys | null> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(KEY_STORE_NAME, 'readonly');
            const store = transaction.objectStore(KEY_STORE_NAME);
            const request = store.get('my_keys');

            request.onsuccess = () => resolve(request.result || null);
            request.onerror = () => reject('Failed to load identity keys');
        });
    }

    /**
     * Save a message locally
     */
    public static async saveMessage(message: LocalMessage): Promise<void> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readwrite');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.put(message);

            request.onsuccess = () => resolve();
            request.onerror = () => reject('Failed to save message');
        });
    }

    /**
     * Load messages for a specific conversation
     */
    public static async getMessages(chatPartnerId: string): Promise<LocalMessage[]> {
        const db = await this.getDB();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction(STORE_NAME, 'readonly');
            const store = transaction.objectStore(STORE_NAME);
            const request = store.getAll();

            request.onsuccess = () => {
                const allMessages: LocalMessage[] = request.result;
                const filtered = allMessages.filter(
                    msg => msg.sender_id === chatPartnerId || msg.recipient_id === chatPartnerId
                );
                // Sort by timestamp
                filtered.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
                resolve(filtered);
            };

            request.onerror = () => reject('Failed to load messages');
        });
    }

    /**
     * Wipe all local data (Call on logout)
     */
    public static async wipeAllData(): Promise<void> {
        this.db = null;
        return new Promise((resolve, reject) => {
            const request = indexedDB.deleteDatabase(DB_NAME);
            request.onsuccess = () => resolve();
            request.onerror = () => reject('Failed to delete database');
        });
    }
}
