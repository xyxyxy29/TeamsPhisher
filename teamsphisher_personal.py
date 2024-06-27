import requests
import json
import sys
import re
import urllib

SEARCH_USERS_API_URL = "https://teams.live.com/api/mt/beta/users/searchUsers"
CREATE_GROUP_API_URL = "https://teams.live.com/api/groups/beta/groups/create"
SEND_MESSAGE_API_URL = "https://msgapi.teams.live.com/v1/users/ME/conversations/{}/messages"

def search_users(authorization_header, x_skypetoken_header, email):
    headers = {
        'Authorization': authorization_header,
        'X-Skypetoken': x_skypetoken_header,
        'Content-Type': 'application/json'
    }

    data = {
        'emails': [email],
        'phones': []
    }

    try:
        response = requests.post(SEARCH_USERS_API_URL, headers=headers, data=json.dumps(data))
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)

        json_response = response.json()
        


        # Extracting the mri and first name value
        user_profiles = json_response.get(email, {}).get('userProfiles', [{}])
        mri_value = user_profiles[0].get('mri', '')
        display_name = user_profiles[0].get('displayName', '')
        
   #     first_name = extract_first_name(display_name)
   
        # Extract first name from email username. To customize if necessary!!
        email_username = email.split('@')[0]
        first_name = extract_first_name_from_email(email_username)

        return mri_value, first_name

    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
    except requests.exceptions.RequestException as err:
        print(f"Request Exception: {err}")
        
        
def extract_first_name_from_email(email_username):
    # Assuming email username is in the format firstname.lastname
    first_name = email_username.split('.')[0]
    return first_name.capitalize()
        
def sender_mri_value(x_skypetoken_header):
    """
    Format the x_skypetoken_header, update endpoint, and return the specified string.

    Parameters:
    - x_skypetoken_header (str): The x_skypetoken header value.

    Returns:
    - str: String between "ea.notifications.skype.comusers/" and "/endpoints/".
    """

    # Append 'skypetoken=' prefix
    formatted_header = f'skypetoken={x_skypetoken_header}'

    # Construct the PUT request data
    put_url = "https://msgapi.teams.live.com/v2/users/ME/endpoints/97aa1db3-87bb-4c8c-adca-b92f88663a13"
    headers = {
        'Authentication': formatted_header,
        'Content-Type': 'application/json'
    }
    

    data = {
        "endpointFeatures": "Agent,Presence2015,MessageProperties,CustomUserProperties,NotificationStream,SupportsSkipRosterFromThreads",
        "startingTimeSpan": 0,
        "subscriptions": [
            {"channelType": "TrouterPush", "interestedResources": ["/v1/users/ME/conversations/ALL/properties", "/v1/users/ME/conversations/ALL/messages", "/v1/threads/ALL"]},
            {"channelType": "PushNotification", "interestedResources": ["/v1/users/ME/conversations/ALL/properties", "/v1/users/ME/conversations/ALL/messages", "/v1/threads/ALL"]}
        ]
    }

    # Send the PUT request
    put_response = requests.put(put_url, headers=headers, json=data)
    put_response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)

    # Extract the desired string from the response
    response_text = put_response.text
    start_index = response_text.find("ea.notifications.skype.comusers/") + len("ea.notifications.skype.comusers/")
    end_index = response_text.find("/endpoints/", start_index)
    result_string = response_text[start_index:end_index]

    return result_string

def create_group(authorization_header, x_skypetoken_header, mri_value):
    
    sender_mri = sender_mri_value(x_skypetoken_header)
    
    headers = {
        'Authorization': authorization_header,
        'X-Skypetoken': x_skypetoken_header,
        'Content-Type': 'application/json'
    }
    
    ### need to retrieve sender mri value
    data = {
        "members": [
            {"id": mri_value, "role": "User"},
            {"id": sender_mri, "role": "User"}
        ],
        "properties": {
            "threadType": "chat",
            "isStickyThread": "true"
        }
    }

    try:
        response = requests.post(CREATE_GROUP_API_URL, headers=headers, data=json.dumps(data))
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)

        return response.json()

    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
        return None
    except requests.exceptions.RequestException as err:
        print(f"Request Exception: {err}")
        return None

def send_message(authorization_header, x_skypetoken_header, thread_id, message_body):
    headers = {
        'Authorization': authorization_header,
        'X-Skypetoken': x_skypetoken_header,
        'Content-Type': 'application/json'
    }

    message_url = SEND_MESSAGE_API_URL.format(thread_id)

    data = {
        "content": message_body,
        "messagetype": "RichText/Html",
        "contenttype": "text",
        "amsreferences": [],
        "clientmessageid": "364997573041940412",
        "imdisplayname": "Microsoft Identity Protection",
        "properties": {
            "importance": "",
            "subject": ""
        }
    }

    try:
        response = requests.post(message_url, headers=headers, data=json.dumps(data))
        response.raise_for_status()  # Raise an error for bad responses (4xx or 5xx)

        return response.json()

    except requests.exceptions.HTTPError as errh:
        print(f"HTTP Error: {errh}")
        return None
    except requests.exceptions.RequestException as err:
        print(f"Request Exception: {err}")
        return None

def get_cookies(username, password):
    preflight_url = "https://login.live.com/oauth20_authorize.srf?client_id=5e3ce6c0-2b1f-4285-8d4b-75ee78787346&scope=openid+profile&response_type=id_token&nonce=dc6df607-df9e-4db8-8a25-3ff36a46a66b"
    login_url = "https://login.live.com/ppsecure/post.srf"

    try:
        preflight_response = requests.get(preflight_url)
        preflight_response.raise_for_status()  # Check for HTTP errors

        # Extract MSPOK and OParams cookies and PPFT value from the response
        mspok_cookie = preflight_response.cookies.get('MSPOK')
        oparams_cookie = preflight_response.cookies.get('OParams')
        ppft_byte = re.search(b'id="i0327"\ value="([^"]+)', preflight_response.content)
        ppft = ppft_byte.group(1).decode('utf-8')

        # Build authenticated cookie header
        # Step 1: Send POST request to login_url
        login_data = f"login={urllib.parse.quote(username)}&passwd={urllib.parse.quote(password)}&PPFT={urllib.parse.quote(ppft)}"

        login_headers = {
            "Cookie": f"MSPOK={mspok_cookie}; OParams={oparams_cookie}",
            "Content-Type": "application/x-www-form-urlencoded"
        }

        login_response = requests.post(login_url, headers=login_headers, data=login_data)
        # Extract cookies from the response headers
        cookies = login_response.cookies.get_dict()

        # Extract required cookies
        host_msaauth_cookie = cookies.get("__Host-MSAAUTH", "")
        oparams_cookie = cookies.get("OParams", "")

        
        # Check if host_msaauth_cookie is empty
        if not host_msaauth_cookie:
            print("Incorrect Username/Password")
            sys.exit(1)

        # Step 2: Send GET request to authorize_url
        authentication_cookies = {
            "Cookie": f"__Host-MSAAUTH={host_msaauth_cookie}; OParams={oparams_cookie}"
        }


        return authentication_cookies

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None, None

def retrieve_authorization_header_search(authentication_cookies):
    authorize_url = "https://login.live.com/oauth20_authorize.srf?client_id=4b3e8f46-56d3-427f-b1e2-d239b2ea6bca&scope=service%3a%3aapi.fl.teams.microsoft.com%3a%3aMBI_SSL+openid+profile&response_type=token"

    authorize_response = requests.get(authorize_url, headers=authentication_cookies, allow_redirects=False)
    # Extract authorization_header_search from the Location header
    location_header = authorize_response.headers.get("Location", "")

    # authorization_header_search = re.search(r'access_token=(.*?)&', location_header)
    match = re.search(r'access_token=([^&]+)', location_header)
    if match:
        access_token = match.group(1)

        # Add "Bearer " prefix
        authorization_header_search = f"Bearer {access_token}"

    else:
        print("Access token not found in the URL.")

    return authorization_header_search

def get_x_skypetoken_header(authentication_cookies):
    skype_authorize_url = "https://login.live.com/oauth20_authorize.srf?client_id=4b3e8f46-56d3-427f-b1e2-d239b2ea6bca&scope=service%3a%3aapi.fl.spaces.skype.com%3a%3aMBI_SSL+openid+profile&response_type=token"
    skype_token_url = "https://teams.live.com/api/auth/v1.0/authz/consumer"

    skype_authorize_response = requests.get(skype_authorize_url, headers=authentication_cookies, allow_redirects=False)
    skype_authorize_response.raise_for_status()

    skype_location_header = skype_authorize_response.headers.get("Location", "")

    match = re.search(r'access_token=([^&]+)', skype_location_header)

    skype_access_token = match.group(1)

    # Add "Bearer " prefix
    skype_token_authorization_header = f"Bearer {skype_access_token}"

    # Retrieve skype token
    skype_token_headers = {
        'Authorization': skype_token_authorization_header,
    }
    skype_token_response = requests.post(skype_token_url, headers=skype_token_headers, allow_redirects=False)
    skype_token_response.raise_for_status()

    # Parse the JSON response
    skype_data = skype_token_response.json()

    # authorization_header_search = re.search(r'access_token=(.*?)&', location_header)
    x_skypetoken_header = skype_data.get("skypeToken", {}).get("skypetoken")

    return x_skypetoken_header

def retrieve_authorization_header_group(authentication_cookies):
    authorize_url = "https://login.live.com/oauth20_authorize.srf?client_id=4b3e8f46-56d3-427f-b1e2-d239b2ea6bca&scope=https%3a%2f%2fgroupssvc.fl.teams.microsoft.com%2fteams.readwrite+openid+profile&response_type=token"

    authorize_response = requests.get(authorize_url, headers=authentication_cookies, allow_redirects=False)
    # Extract authorization_header_search from the Location header
    location_header = authorize_response.headers.get("Location", "")

    # authorization_header_search = re.search(r'access_token=(.*?)&', location_header)
    match = re.search(r'access_token=([^&]+)', location_header)
    if match:
        access_token = match.group(1)

        # Add "Bearer " prefix
        authorization_header_group = f"Bearer {access_token}"

    else:
        print("Access token not found in the URL.")

    return authorization_header_group

def read_emails_from_file(file_path):
    with open(file_path, 'r') as file:
        emails = [line.strip().lower() for line in file]
    return emails

def read_message_body_from_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        message_body = file.read()
        
    return message_body

def extract_first_name(display_name):
    return display_name.split()[0] if display_name else ""

def personalize_message(greeting, first_name):
    return f"{greeting} {first_name},</p><p>&nbsp;</p>"

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python script.py <Message_Body_File> <Email_or_Email_File> <username> <password> [--personalize]")
        sys.exit(1)

    message_body_file = sys.argv[1]
    email_or_file_path = sys.argv[2]
    username = sys.argv[3]
    password = sys.argv[4]

    authentication_cookies = get_cookies(username, password)

    authorization_header_search = retrieve_authorization_header_search(authentication_cookies)

    x_skypetoken_header = get_x_skypetoken_header(authentication_cookies)

    authorization_header_group = retrieve_authorization_header_group(authentication_cookies)

    personalize_message_flag = "--personalize" in sys.argv

    # Read message body from file
    message_body = read_message_body_from_file(message_body_file)


    # Determine if the input is a file or a single email
    if email_or_file_path.endswith('.txt'):
        emails = read_emails_from_file(email_or_file_path)
    else:
        emails = [email_or_file_path]

    success_count = 0
    failure_count = 0
    


    for email in emails:
    
        try:
        
            mri_value, first_name = search_users(authorization_header_search, x_skypetoken_header, email)

            if mri_value:
                group_creation_result = create_group(authorization_header_group, x_skypetoken_header, mri_value)

                # Extracting threadId from the response
                thread_id = group_creation_result.get('value', {}).get('threadId', '')

                if thread_id:
                    # Personalize message if flag is provided
                    if personalize_message_flag:
        
                        personalized_greeting = personalize_message("<p>Hi", first_name)
                        message_body = f"{personalized_greeting}{message_body}"

                    # Sending the message

                    send_message_result = send_message(authorization_header_group, x_skypetoken_header, thread_id, message_body)
                    message_body = read_message_body_from_file(message_body_file)

                    if send_message_result:
                        print(f"Message sent successfully to {email}")
                        success_count += 1
                    else:
                        print(f"Failed to send message to {email}")
                        failure_count += 1
                else:
                    print(f"Thread ID not found for {email}.")
                    failure_count += 1
            else:
                print(f"MRI Value not found for {email}.")
                failure_count += 1
        
        except Exception as e:
            print(f"Failed to send message to {email}. Error: {e}")
            failure_count += 1

    print("\nSummary:")
    print(f"Success count: {success_count}")
    print(f"Failure count: {failure_count}")
