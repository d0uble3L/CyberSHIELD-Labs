import re

def check_password_strength(password):
    # Criteria for password strength
    length_criteria = len(password) >= 8
    digit_criteria = re.search(r'\d', password) is not None
    lowercase_criteria = re.search(r'[a-z]', password) is not None
    uppercase_criteria = re.search(r'[A-Z]', password) is not None
    special_char_criteria = re.search(r'[!@#$%^&*(),.?":{}|<>]', password) is not None

    # Evaluate strength
    criteria = [length_criteria, digit_criteria, lowercase_criteria, uppercase_criteria, special_char_criteria]
    strength = sum(criteria)

    if strength == 5:
        return "Very Strong"
    elif strength == 4:
        return "Strong"
    elif strength == 3:
        return "Moderate"
    else:
        return "Weak"

if __name__ == "__main__":
    password = input("Enter a password to check its strength: ")
    strength = check_password_strength(password)
    print(f"Password strength: {strength}")
