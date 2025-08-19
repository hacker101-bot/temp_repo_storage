lucky = 13
guessed = True

while guessed == True:
    print("Guess my number:")
    guess = int(input())
if guess == lucky:
    print("Amazing, you guessed it")
    guessed = False
else:
       print(f"Sorry, it’s not {guess}")
print("Nice playing with you")
