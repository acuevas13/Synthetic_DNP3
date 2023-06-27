import numpy as np
from collections import defaultdict

"""
Data Preprocessing: Parse your network capture files (pcap files) to extract the DNP3 traffic. For each packet, 
you will want to extract relevant attributes such as the type of message, length, timestamp, source, destination,
and perhaps specific parts of the payload.

State Identification: Identify the different states your system can be in. In DNP3 traffic, a state could be 
represented by the type of the message (e.g., read, write, etc.) or even combinations of message attributes.

Transition Probability Matrix: Analyze your preprocessed data to determine the transition probabilities 
between states. This is a matrix where the cell in the i-th row and j-th column is the probability of transitioning 
from state i to state j. The sum of each row in the matrix should be 1 (representing a 100% chance of moving to some state from the current one).

Generate Synthetic Traffic: Starting from an initial state, use the transition matrix to probabilistically 
determine the next state, and thus the next message to send in your synthetic traffic. Repeat this process as 
many times as necessary to generate your synthetic traffic.

Validation: Validate your synthetic traffic by comparing its statistics (message frequency, read/write ratio, etc.) to 
those of the real traffic. You can also use more advanced techniques like sequence alignment or machine learning models 
trained on the real traffic to evaluate how realistic the synthetic traffic is.
"""

def transitionPropertyMatrix(states, states_sequence):
# Initialize a dictionary to count state transitions
    transition_counts = defaultdict(lambda: defaultdict(int))

    # Count the transitions from state to state
    for i in range(len(state_sequence) - 1):
        curr_state = state_sequence[i]
        next_state = state_sequence[i + 1]
        transition_counts[curr_state][next_state] += 1

    # Create an empty transition matrix
    transition_matrix = np.zeros((len(states), len(states)))

    # Fill the transition matrix with transition probabilities
    for i, from_state in enumerate(states):
        total_from_state_transitions = sum(transition_counts[from_state].values())
        for j, to_state in enumerate(states):
            if total_from_state_transitions > 0:
                transition_matrix[i, j] = transition_counts[from_state][to_state] / \
                    total_from_state_transitions

    # Print the transition matrix
    print(transition_matrix)


def test_transitionPropertyMatrix():
    # Define your sequence of states
    state_sequence = ['read', 'response', 'read', 'response', 'select', 'operate',
                      'confirm', 'read', 'response', 'select', 'operate', 'confirm', ...]

    # Define your states
    states = ['read', 'response', 'select', 'operate', 'confirm']
    
    transitionPropertyMatrix(states, state_sequence)
    

def generate_traffic(transition_matrix, states):
    def generate_state(current_state, transition_matrix, states):
        # Choose a state for the next step based on the transition probabilities
        return np.random.choice(states, p=transition_matrix[current_state])

    # Define the initial state, can also be randomly chosen
    current_state = 'read'

    # Define the number of steps to generate
    num_steps = 100

    # Generate the synthetic traffic
    synthetic_traffic = [current_state]
    for _ in range(num_steps):
        current_state = generate_state(current_state, transition_matrix, states)
        synthetic_traffic.append(current_state)

    # Print the synthetic traffic
    print(synthetic_traffic)
