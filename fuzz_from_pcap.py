from scapy.all import *
import sys

MUTATE_PERCENTAGE = 0.01

def flip_bit(data):
    num_flips = int((len(data)) * MUTATE_PERCENTAGE)
    idxs = range(len(data) - 1)

    chosen_idxs = set()

    while len(chosen_idxs) < num_flips:
        chosen_idxs.add(random.choice(idxs))

    for x in chosen_idxs:
        data[x] = data[x] ^ 0xff

    return data


def mutate(input_bytes):
    new_data = flip_bit(input_bytes)
    return new_data


def send_payload(payload, host, port, dbg=True):
    print(f"Sending payload:\n{payload}")
    print()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.send(payload)
        if dbg == True:
            print(f"Received:\n{s.recv(300).hex()}")
    except KeyboardInterrupt:
        print(f"[!] Exiting Ctrl-C\n")
        sys.exit(1)
    except:
        pass
    finally:
        s.close()


def fuzz_with_payloads(payloads, host, port):
    print(f"[*] Starting the fuzzing process...")
    while True:
        rand_pkt = random.choice(payloads)
        mutated_pkt = mutate(rand_pkt)
        send_payload(mutated_pkt, host, port)


def extract_packet_data(pcap_fpath, port):
    payloads = []
    pcaps = rdpcap(pcap_fpath)
    sessions = pcaps.sessions()
    for session in sessions:
        for packet in sessions[session]:
            try:
                if packet[TCP].dport == port:
                    payload = bytes(packet[TCP].payload)
                    payload = bytearray(payload)
                    payloads.append(payload)

            except Exception as e:
                print(e)

    print(f"[*] Parsed Pcap got {len(payloads)} packets")
    return payloads


if len(sys.argv) != 4:
    print(f"Usage: python3 {sys.argv[0]} <pcap> <target host/ip> <port>")
    sys.exit(1)


fpath = sys.argv[1]
host = sys.argv[2]
port = int(sys.argv[3])

payloads = extract_packet_data(fpath, port)

fuzz_with_payloads(payloads, host, port)
