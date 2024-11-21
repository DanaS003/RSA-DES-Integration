import ast
import random
import string


def string_to_list(input_string):
    try:
        result = ast.literal_eval(input_string)
        if isinstance(result, list) and all(isinstance(item, int) for item in result):
            return result
        else:
            raise ValueError("The input string is not a valid list of integers.")
    except (ValueError, SyntaxError):
        raise ValueError("Invalid input string format. Ensure it represents a list of integers.")
    
    
def generate_des_key():
    # Define the characters to choose from (letters and digits)
    characters = string.ascii_letters + string.digits
    
    # Randomly select characters and join them into a string
    random_string = ''.join(random.choice(characters) for _ in range(8))
    
    return random_string


def generate_random_nonce(length=8):
    return ''.join([str(random.randint(0, 9)) for i in range(length)])




