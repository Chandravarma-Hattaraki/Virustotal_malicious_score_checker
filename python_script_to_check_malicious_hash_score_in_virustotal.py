import requests
import pandas as pd
import time

# Replace 'your_api_key' with your actual VirusTotal API key
api_key = '<your_api_key>'

# Replace 'excel_filename' with the path to your input Excel file
excel_filename = "/Users/chandravarma/Desktop/hash.xlsx"  
df = pd.read_excel(excel_filename)
output_excel_filename = "/Users/chandravarma/Desktop/hash_results.xlsx"
dataframes = []

# Define the delay between each request in seconds
request_delay = 15  # Adjust as needed to stay within the rate limit

for hash_value in df['Hash']:  # Iterate over the values in the 'Hash' column
    url = f'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': api_key, 'resource': hash_value}
    
    try:
        response = requests.get(url, params=params)
        result = response.json()

        if result['response_code'] == 1:
            # Create a DataFrame with hash value and number of positives
            score = pd.DataFrame({'Hash': [hash_value], 'Positives': [result['positives']]})
            dataframes.append(score)
        else:
            print(f"Error: Unable to get information for hash '{hash_value}' from VirusTotal.")
    except requests.exceptions.JSONDecodeError:
        print(f"Error: Unable to decode JSON response for hash '{hash_value}'.")

    # Pause for the specified delay to comply with the rate limit
    time.sleep(request_delay)

# Concatenate all DataFrames into one DataFrame
score_data = pd.concat(dataframes, ignore_index=True)

# Save the DataFrame to an Excel file
score_data.to_excel(output_excel_filename, index=False)

print('Results saved to:', output_excel_filename)
