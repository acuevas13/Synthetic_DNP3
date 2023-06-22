def find_candidate_cycles(lst):
    cycles = []
    current_cycle = []

    for letter in lst:
        if letter in current_cycle:
            cycles.append(current_cycle)
            current_cycle = [letter]
        else:
            current_cycle.append(letter)

    if current_cycle:
        cycles.append(current_cycle)

    return cycles

def my():
    original_list = [(1, 'apple'), (2, 'banana'), (3, 'apple'), (4, 'orange')]

    condition = ['apple']

    subset = [item for item in original_list if item[1] in condition]
    return subset



def find_identical_lists(list_of_lists, N):
    groups = {}
    for lst in list_of_lists:
        key = frozenset(lst)  # Convert the list to a hashable frozenset
        if key not in groups:
            groups[key] = []
        groups[key].append(lst)
    
    return [lst for lst in groups.values() if len(lst) >= N]


# groups = []
# for lst in lists:
#     key = tuple(sorted(lst))
#     found = False
#     for i, (existing_key, group) in enumerate(groups):
#         if existing_key == key:
#             group.append(lst)
#             found = True
#             break
#     if not found:
#         groups.append((key, [lst]))




# Example usage
# letters = ['a', 'b', 'c', 'd', 'c', 'd', 'b', 'a', 'd', 'c', 'b', 'a', 'a', 'b', 'c', 'd']
# candidate_cycles = find_candidate_cycles(letters)
# print(candidate_cycles)
# result = find_identical_lists(candidate_cycles, 2)
# print(result)
# # # print()
letters = ['a', 'a', 'a', 'a', 'b', 'a', 'a',
           'a', 'a', 'b', 'a', 'c', 'a', 'a', 'a', 'a']
candidate_cycles = find_candidate_cycles(letters)
print(candidate_cycles)
result = find_identical_lists(candidate_cycles, 3)
print(result)