import tkinter as tk
from tkinter import ttk
import paho.mqtt.client as mqtt
from meshtastic import mesh_pb2, mqtt_pb2, portnums_pb2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import sqlite3
import threading


# MQTT broker details
MQTT_BROKER = "mqtt.meshtastic.org"
MQTT_PORT = 1883
MQTT_USERNAME = "meshdev"
MQTT_PASSWORD = "large4cats"
ROOT_TOPIC = "msh/ANZ/#"

KEY = '1PG7OiApB1nwvP+rz05pAQ=='

# Initialize tkinter
root = tk.Tk()
root.title("MQTT Topics")
root.geometry("800x600")  # Width x Height

# Initialize MQTT client
client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
client.username_pw_set(MQTT_USERNAME, MQTT_PASSWORD)

# Initialize Treeview
left_panel = ttk.Frame(root)
left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
tree = ttk.Treeview(left_panel)
tree.pack(expand=True, fill=tk.BOTH)

# Label to display selected topic
right_panel = ttk.Frame(root)
right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
topic_label = ttk.Label(right_panel, text="")
topic_label.pack(padx=10, pady=10)

class DecodedMessagesDB:
    def __init__(self, db_file=None):
        self.db_file = db_file
        self.conn = None
        self.cursor = None
        self.create_connection()

    def create_connection(self):
        self.conn = sqlite3.connect(self.db_file) if self.db_file else sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        self.create_table()

    def create_table(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS decoded_messages (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                sender_id INTEGER,
                                receiver_id INTEGER,
                                channel INTEGER,
                                portnum INTEGER,
                                payload TEXT,
                                message_id INTEGER,
                                hop_limit INTEGER,
                                timestamp INTEGER,
                                topic TEXT
                             )''')
        self.conn.commit()

    def insert_decoded_message(self, sender_id, receiver_id, channel, portnum, payload, message_id, hop_limit, timestamp, topic):
        try:
            self.cursor.execute('''INSERT INTO decoded_messages 
                                  (sender_id, receiver_id, channel, portnum, payload, message_id, hop_limit, timestamp, topic) 
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                 (sender_id, receiver_id, channel, portnum, payload, message_id, hop_limit, timestamp, topic))
            self.conn.commit()
            print("Message stored in the database successfully.")
        except sqlite3.Error as e:
            print(f"SQLite error occurred: {e}")


db = DecodedMessagesDB('decoded_messages.db')

def on_connect(client, userdata, flags, rc, properties=None):
    if rc == 0:
        print("Connected to MQTT broker")
        client.subscribe(ROOT_TOPIC)
    else:
        print("Failed to connect, return code:", rc)

def on_item_select(event):
    selected_item = tree.item(tree.focus())
    selected_topic = selected_item['text']
    if selected_topic and not tree.get_children(tree.focus()):
        last_message = get_last_message(selected_topic)
        if last_message:
            topic_label.config(text=f"{selected_topic}: {last_message}")
        else:
            topic_label.config(text=f"No message found for topic {selected_topic}")

def get_last_message(topic):
    # TODO: implement logic to retrieve last message for topic
    return "Last message for topic: " + topic


def update_treeview(parent, item):
    if isinstance(item, dict):
        for key, value in item.items():
            existing_child = None
            for child_id in tree.get_children(parent):
                if tree.item(child_id)["text"] == key:
                    existing_child = child_id
                    break
            if existing_child:
                update_treeview(existing_child, value)
            else:
                if isinstance(value, dict) and len(value) == 1 and next(iter(value)) == '':
                    child = tree.insert(parent, 'end', text=key)
                    update_treeview(child, value[''])
                else:
                    child = tree.insert(parent, 'end', text=key)
                    update_treeview(child, value)
    elif isinstance(item, list):
        for value in item:
            tree.insert(parent, 'end', text=value)


def process_message(mp, text_payload, is_encrypted, mqtt_msg):
    topic = mqtt_msg.topic
    mp_id = getattr(mp, "id")
    mp_to = getattr(mp, "to")
    mp_from = getattr(mp, "from")
    mp_portnum = mp.decoded.portnum
    mp_payload = mp.decoded.payload
    mp_hop_limit = mp.hop_limit
    timestamp = mp.rx_time
    print(mp)

    try:
        root.after(0, db.insert_decoded_message, mp_from, mp_to, mp.channel, mp_portnum, mp_payload, mp_id, mp_hop_limit, timestamp, topic)
    except Exception as e:
        print(f"Error storing message in the database: {e}")




def decode_encrypted(message_packet, mqtt_msg):
    try:
        key_bytes = base64.b64decode(KEY.encode('ascii'))
        nonce_packet_id = getattr(message_packet, "id").to_bytes(8, "little")
        nonce_from_node = getattr(message_packet, "from").to_bytes(8, "little")
        nonce = nonce_packet_id + nonce_from_node

        cipher = Cipher(algorithms.AES(key_bytes), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(getattr(message_packet, "encrypted")) + decryptor.finalize()

        data = mesh_pb2.Data()
        data.ParseFromString(decrypted_bytes)
        message_packet.decoded.CopyFrom(data)

        if message_packet.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
            text_payload = message_packet.decoded.payload.decode("utf-8")
            is_encrypted = True
            process_message(message_packet, text_payload, is_encrypted, mqtt_msg)

    except Exception as e:
        pass


def on_message(client, userdata, msg):
    topic = msg.topic
    mqtt_msg = msg
    service_envelope = mqtt_pb2.ServiceEnvelope()
    message_packet = None

    try:
        service_envelope.ParseFromString(msg.payload)
        message_packet = service_envelope.packet

    except Exception as e:
        pass

    if message_packet is not None:
        if message_packet.HasField("encrypted") and not message_packet.HasField("decoded"):
            decode_encrypted(message_packet, mqtt_msg)

    topic_segments = topic.split('/')[::-1]
    data = {}
    for segment in topic_segments:
        if segment:
            if segment == 'msh' and 'msh' in data:
                data['msh'].update({'': data.pop('msh')})
            elif segment in data:
                data[segment].update({'': data.pop(segment)})
            else:
                data = {segment: data}

    update_treeview('', data)


client.on_connect = on_connect
client.on_message = on_message
client.connect(MQTT_BROKER, MQTT_PORT, 60)
client.loop_start()

tree.bind('<<TreeviewSelect>>', on_item_select)

root.mainloop()

db.close()
