from flask import request, session
from flask_socketio import emit, join_room, leave_room
from db import update_user_status
from services import quantum_service

def register_socket_events(socketio):
    
    @socketio.on('connect')
    def handle_connect():
        if 'username' in session:
            username = session['username']
            # Join a room named after the username for direct messaging
            join_room(username)
            update_user_status(username, True)
            print(f"User {username} connected")
            
            # Broadcast user online status to everyone
            emit('user_status', {'username': username, 'is_online': True}, broadcast=True)
            
            # Initialize/Update keys for this user in the crypto service
            # In a real app, we might load persistent keys or generate new ephemeral ones
            if username not in quantum_service.user_keypairs:
                quantum_service.generate_user_keypairs(username)
        else:
            print("Anonymous connection")

    @socketio.on('disconnect')
    def handle_disconnect():
        if 'username' in session:
            username = session['username']
            update_user_status(username, False)
            print(f"User {username} disconnected")
            emit('user_status', {'username': username, 'is_online': False}, broadcast=True)

    @socketio.on('send_message')
    def handle_message(data):
        """
        Handle incoming message.
        Data format expected:
        {
            'recipient_id': 'username',
            'encrypted_message': '...',
            'timestamp': '...',
            ...
        }
        """
        sender_id = session.get('username')
        if not sender_id:
            return
            
        recipient_id = data.get('recipient_id')
        
        # Add sender info
        data['sender_id'] = sender_id
        
        # Forward to recipient
        # Note: We do NOT store the message in the database (Ephemeral)
        emit('new_message', data, room=recipient_id)
        
        # Also send back to sender for their UI (optimistic update usually handles this, but good for confirmation)
        # emit('message_sent', data, room=sender_id)
    
    @socketio.on('relay_quantum_signal')
    def handle_relay_signal(data):
        """
        Relay quantum/PQC signaling data between peers.
        Used for client-side BB84 and Kyber handshakes.
        Data format:
        {
            'recipient_id': 'username',
            'type': 'bb84_photons' | 'bb84_bases' | 'kyber_ciphertext',
            'payload': { ... }
        }
        """
        sender_id = session.get('username')
        if not sender_id:
            return
            
        recipient_id = data.get('recipient_id')
        if not recipient_id:
            return
            
        # Add sender info for the recipient to know who sent the signal
        data['sender_id'] = sender_id
        
        # Forward the signal to the specific recipient room
        emit('quantum_signal', data, room=recipient_id)

    # Quantum Key Exchange Signaling (Legacy/Relay version)
    @socketio.on('initiate_key_exchange')
    def handle_key_exchange(data):
        sender_id = session.get('username')
        recipient_id = data.get('recipient_id')
        
        if not sender_id or not recipient_id:
            return

        # Perform server-side quantum simulation/exchange
        result = quantum_service.initiate_quantum_key_exchange(sender_id, recipient_id)
        
        # Notify both parties
        emit('key_exchange_complete', result, room=sender_id)
        emit('key_exchange_complete', result, room=recipient_id)

    @socketio.on('request_public_keys')
    def handle_public_keys_request(data):
        # Return all public keys (simplified for demo)
        keys = quantum_service.get_all_users()
        emit('public_keys_update', keys)
