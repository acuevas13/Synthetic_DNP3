


# 1.) Multiplexer: 
# Input:  (.pcap) file
# Output: (list) shortLived_flows  - Connections (< 1 sec) grouped by (IP Protocol, Server Port, Client Address) 
#         (list) longLived_flows - Connections grouped by (IP Protocol, Server Port, Client Address, Client Port)


# 2.) Tokenizer: 
# Input:  (.pcap) file 
#         (list) shortLived_flows and longLived_flows
# Output: (dict) tokenized_shortLived_flows -  [Key]: (tuple) Flow, [Value]: (list of tuple) List of tokenized packets in this flow
#         (dict) tokenized_longLived_flows -  [Key]: (tuple) Flow, [Value]: (list of tuple) List of tokenized packets in this flow
#             Request:
#                Tuple - (timestamp, messageIdentifier, pathIdentifier)
#             Response: 
#                Tuple - (timestamp, pathIdentifier)




# Algorithm 1. Learner module algorithm.
#Input: A tokenized flow and parameters N; ε; dur_thr
#Output: A list of tuples (request set, dur_min; dur_max; dur_std)

# Step 1: group requests
# count request occurrences;
#     group requests with same counter  + or - ε;
#     for each group do
#         for each subset in group do
#             # Step 2: find candidates n/
#             for each request in subset do
#                 candidates’N repeating cycles;
#                 # Step 3: test candidates n/
#                 dur_min; dur_max <- minimum and maximum candidate durations;
#                 if dur_max - dur_min < dur_thr
#                     dur_std <- cycle duration standard deviation;
#                     store (request set, dur_min; dur_max; dur_std);
#                     continue to next subset;
#                 else
#                     reset candidates;
#             end
#             ignore remaining subset requests as non-periodic;
#     end
# end