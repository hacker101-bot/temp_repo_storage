import random
import string

alphabet = string.ascii_letters + string.digits
numbers = string.digits

# Convert alphabet to a list before shuffling
alphabet_list = list(alphabet)
random.SystemRandom().shuffle(alphabet_list)

# If you want it back as a string
alphabet = ''.join(alphabet_list)

print(alphabet)
