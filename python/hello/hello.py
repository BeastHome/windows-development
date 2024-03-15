# Requesting input from the user
input_name = input ('What is your name?\n')

# Defining a function to process the data
def myFunc(user_name):
    # The match and case statements evaluate the input and act upon it according to the rules defined
    match user_name:
        case 'Dave' | 'David':
            # Standard print statement
            return ('Dave\'s not here man...')

        # If an exact match is not confirmed, this last case will be used if provided
        case _:
            # The f before the string to be printed allows you to use a variable within {} to 
            # print a vairable in the string with no extra spaces.
            return (f'Hello {user_name}.')

# Calls the function defined previously
print (myFunc(input_name))