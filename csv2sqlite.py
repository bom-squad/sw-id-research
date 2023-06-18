import sys
import pandas as pd
import sqlite3

# Check if the CSV filename is provided as a command line argument
if len(sys.argv) < 2:
    print("Please provide the CSV filename as a command line argument.")
    sys.exit(1)

# Get the CSV filename from the command line argument
csv_file = sys.argv[1]

# Extract the filename without extension
filename = csv_file.split('/')[-1].split('.')[0]

# Define the SQLite database filename
db_file = f'{filename}.db'

# Read the CSV file into a DataFrame
df = pd.read_csv(csv_file)

# Create a connection to the SQLite database
conn = sqlite3.connect(db_file)

# Write the DataFrame to a table in the database
df.to_sql(filename, conn, index=False, if_exists='replace')

# Close the database connection
conn.close()

# Confirmation message
print(f"SQLite database '{db_file}' has been created.")
