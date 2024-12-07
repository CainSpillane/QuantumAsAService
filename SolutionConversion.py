# Import necessary libraries
import sys

# Function to read IP mapping from a file
def load_ip_mapping(file_path):
    """
    Load the IP mapping from a text file.

    Args:
    - file_path (str): Path to the text file containing the IP mapping.

    Returns:
    - dict: A dictionary mapping each binary position to an IP address.
    """
    ip_mapping = {}
    try:
        with open(file_path, 'r') as file:
            for line in file:
                parts = line.strip().split()
                if len(parts) == 2:
                    position = int(parts[0])  # Convert binary position to integer
                    ip_address = parts[1]
                    ip_mapping[position] = ip_address
                else:
                    print(f"Invalid line format: {line}. Skipping.")
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    return ip_mapping

# Function to convert binary string to pfSense firewall commands
def generate_firewall_commands(binary_string, ip_mapping):
    """
    Generate a list of pfSense firewall commands based on a binary string and IP mapping.

    Args:
    - binary_string (str): Binary string indicating network connection states.
    - ip_mapping (dict): A dictionary mapping each binary position to an IP address.

    Returns:
    - list: A list of pfSense firewall commands to execute.
    """
    # Validate input
    if len(binary_string) < 3:
        raise ValueError("Binary string must have at least three digits (2 base nodes and 1 external connection).")

    # Extract base nodes and determine action (block 1's or block 0's)
    base_nodes = binary_string[:2]
    block_action = "1" if base_nodes == "00" else "0" if base_nodes == "11" else None

    if block_action is None:
        raise ValueError("Invalid base node combination. Only '00' or '11' are allowed as base nodes.")

    # Generate pfSense firewall commands
    commands = []
    for index, state in enumerate(binary_string[2:], start=2):  # Skip the first two base node bits
        if state == block_action:  # Block the connections matching the action
            ip_address = ip_mapping.get(index)
            if ip_address:
                commands.append(f"easyrule block em0 {ip_address}")
            else:
                print(f"Warning: No IP address found for binary position {index}. Skipping.")

    return commands

# Example usage
if __name__ == "__main__":
    # Example binary string solution
    binary_string = "00101101"

    # Path to the text file containing the IP mapping
    ip_mapping_file = "mapping.txt"

    try:
        # Load IP mapping from file
        ip_mapping = load_ip_mapping(ip_mapping_file)

        # Generate and print the firewall commands
        firewall_commands = generate_firewall_commands(binary_string, ip_mapping)
        if firewall_commands:
            # print("Generated pfSense firewall commands:")
            for command in firewall_commands:
                print(command)
        else:
            print("No connections need to be blocked based on the input binary string.")
    except ValueError as e:
        print(f"Error: {e}")
