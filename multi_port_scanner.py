#!/usr/bin/env python3
"""
Network Scanner Project
Students: Björn, Daniel, Mattias.K, Lukas.S, Vien
Date: 251021
"""
# Importing modules
from os import environ 
environ["PYGAME_HIDE_SUPPORT_PROMPT"] = "1" #Hides support messsage that pygame prints
from tqdm import tqdm
from colorama import init, Fore
import os
import socket
import sys
import pygame
import time
import random
import pyfiglet

# Init music, pygame.init() in this case makes it so I can use the audio files, pygame.mixer.init() makes it so the music file is ready to load and play
pygame.init() 
pygame.mixer.init()

# Init colors
init()
GREEN = Fore.GREEN
MAGENTA =Fore.MAGENTA
BLUE = Fore.BLUE
RESET = Fore.RESET

# Global list to save ports
open_ports = []

# Set range ports, including the max port
def start_multiscan(target, start_port, max_port, timeout=1.0):

    # Calculation for progress bar
    total_ports = max_port - start_port + 1
    with tqdm(total=total_ports, desc=f"{BLUE}Scanning {target} from [{start_port}] to [{max_port}]", unit="port") as progress_bar:

        # Set range ports, including the max port
        for port in range(start_port, max_port + 1):
            #AF_INET = IPv4, SOCK_STREAM = constant, create a TCP socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Try to connect port with time out
            try:
                s.settimeout(timeout)
                # Returns to 0 if a port is open
                result = s.connect_ex((target, port))
                # If a port is open, add the open port to the open_ports list
                if result == 0:
                    # Try to identify the port service
                    try:
                        # For HTTP-ports
                        if port in (80, 8080):
                            # Sends an HTTP HEAD request to the connected server, asking for only HTTP headers without a body
                            s.sendall(b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % target.encode())
                        # Read max 1024 bytes from the opened socket
                        data = s.recv(1024)
                        # Convert the data and do split and strip empy spaces, and get the first part
                        banner = data.decode(errors="ignore").splitlines()[0].strip()
                        
                        # If the banner exists
                        if banner:
                            # Add open port to the open_ports list
                            open_ports.append(f"Port {port} : Banner {banner}")
                            progress_bar.write(f"\nBanner for {target}:{port} -> {banner}")
                        else:
                            open_ports.append(f"Port {port} : No banner received")
                            progress_bar.write(f"\nNo banner received for {target}:{port}")

                    # Socket timed out error
                    except socket.timeout:
                        open_ports.append(f"Port {port} : No banner (timeout)")
                        progress_bar.write(f"\nNo banner (timeout) for {target}:{port}")
                    # Catch other errors
                    except Exception as e:
                        open_ports.append(f"Port {port} : Error reading banner {e}")
                        progress_bar.write(f"\nError reading banner for {target}:{port}: {e}")
            # DNS lookup failed error
            except socket.gaierror as e:
                progress_bar.write(f"\nHostname could not be resolved. {e}")
                return open_ports
            # Socket error
            except socket.error as e:
                progress_bar.write(f"\nCould not connect to server. {e}")
                return open_ports
            # Close socket
            finally:
                s.close()
                progress_bar.update(1)
                
        # Save port to file
        save_ports_to_file(target, open_ports)

# Save the ports to file, default file name port_results.txt
def save_ports_to_file(target, port_list, file_name="port_results.txt"):

    # Saves only open ports
    if port_list:
        print(f"{GREEN}\nSave ports to file: ") 
        # Print open port(s)
        for port in port_list:
            print(port)    
        
        # Try to save to file
        try:
            with open(file_name, "w") as f:
                f.write(f"Open ports for target IP {target}\n")
                # Separate each line with \n at the end
                for port in port_list:
                    f.write(f"{port}\n")
                # Print out the result of the saved file 
                print(f"{MAGENTA}The results have been saved to the file: {file_name}")

        # File not found error
        except FileNotFoundError:
            print("File not found.")
        # Writing to file errors
        except IOError:
            print("An I/O error occurred.")
        # Other errors
        except:
            print("Something went wrong...")
        # Close file
        f.close()
    else:
        print("\nNo ports are open.")

# Run the program
if __name__ == "__main__":
    
    # Set default timeout to 1s
    timeout = 1

    # Optional CLI arguments, i.e multi_port_scanner.py scanme.nmap.org 1 30 2
    # len(sys.argv) checks are optional CLI arguments.
    # Assume an argument format of <domain name or IP>, <start_port>, <end_port>, <timeout>
    if len(sys.argv) == 5:
        target = socket.gethostbyname(sys.argv[1])
        start_port = int(sys.argv[2])
        max_port = int(sys.argv[3])
        timeout = float(sys.argv[4])

    # Optional CLI arguments, i.e multi_port_scanner.py scanme.nmap.org 1 30
    # len(sys.argv) checks are optional CLI arguments.
    # Assume an argument format of <domain name or IP>, <start_port>, <end_port>.
    elif len(sys.argv) == 4:
        target = socket.gethostbyname(sys.argv[1])
        start_port = int(sys.argv[2])
        max_port = int(sys.argv[3])   
        
    # I.e multi_port_scanner.py scanme.nmap.org
    # With only 2 arguments, it will ask the user to input <start_port> and <end_port>.
    elif len(sys.argv) == 2:
    # Translate hostname to IPv4. It will also accept just the IP.
        target = socket.gethostbyname(sys.argv[1])
        start_port = int(input('starting port: '))
        max_port = int(input('ending port: '))

    # Else inputs from console
    # As last resort, it will ask the user to input IP or domain.
    else: # It will convert <domain name> to IPv4, before asking for <start_port> and <end_port>.
        domain_name = str(input(BLUE + 'Enter target IP or domain: '))
        # Spit url and get the domain name
        if "http" in domain_name:
            target = domain_name.split("://")
            domain_name = target[1]

        target = socket.gethostbyname(domain_name)
        start_port = int(input(BLUE + 'Starting port: '))
        max_port = int(input(BLUE + 'Ending port: '))
        timeout = float(input(BLUE + "Set timout for each port: "))

        play = input("Do you want to hear some music while waiting for the scan to finish? [Yes/No]: ").lower()
        if play == "yes": 
        
            # os.path.join = figuers out if it should use / or \\ depedning on your opearting system, os.path.dirname(__file__) = it finds and opens my music_folder where my Python script is saved
            music_folder = os.path.join(os.path.dirname(__file__), "music_folder")

            # List of music mp3 files that are avalible to play
            music = [
                "Toby Fox - DELTARUNE Chapters 3+4 OST - 20 Raise Up Your Bat.mp3",
                "Toby Fox - DELTARUNE Chapters 3+4 OST - 26 TV WORLD.mp3",
                "32 Attack of the Killer Queen.mp3",
                "23 NOW'S YOUR CHANCE TO BE A.mp3",
                "06 A CYBER'S WORLD-.mp3"
            ]

            # Randomly seclets a music file from the list above
            selected_filename = random.choice(music)

            # os.path.join = figuers out if it should use / or \\ depedning on your opearting system, it opens music_folder and chooses a random music from the music list
            path = os.path.join(music_folder, selected_filename)

            # Loads the music file so it's ready to be used 
            pygame.mixer.music.load(path)

            # Playes the music, loops=0 means it plays once, start=0.0 means it starts from the beginning, fade_ms=2000 means it fades in for 2 seconds
            pygame.mixer.music.play(loops=0, start=0.0, fade_ms=2000)

# Scan the give url with start and end ports
start_multiscan(target, start_port, max_port, timeout)

# Prints "SCAN COMPLETE" in Pyfiglet 
i = pyfiglet.figlet_format("SCAN COMPLETE", font="slant")
print(f"{MAGENTA}" + i)
