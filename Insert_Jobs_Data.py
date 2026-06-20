import psycopg2
from psycopg2 import OperationalError, sql
import pandas as pd
from datetime import datetime
import numpy as np
import os

csv_file = r"C:/DataLoad/Turbohire/Jobs.csv"
# csv_file = r"/home/ec2-user/DataLoad/Turbohire/Jobs.csv"

table_name = 'public.turbohire_jobs_data_stg'
today = datetime.today().strftime('%Y-%m-%d')

def getConnection():
    host = "172.24.0.34"
    dbname = "datamart"
    user = ''
    password = ''
    port = 5432
    
    try:
        conn = psycopg2.connect(
            host=host,
            dbname=dbname,
            user=user,
            password=password,
            port=port
        )
        print("Connection established.")
        return conn
    except OperationalError as e:
        print(f"Connection failed: {e}")
        raise

def parse_datetime(date_str):
    if date_str:
        # Define a list of all the formats you want to support
        date_formats = [
            '%Y-%m-%dT%H:%M:%S',      # Example: 2024-09-23T15:30:00 (ISO format with time)
            '%Y-%m-%d',               # Example: 2024-09-23 (ISO format without time)
            '%d-%m-%Y',               # Example: 23-09-2024 (day-month-year)
            '%d/%m/%Y',               # Example: 23/09/2024 (day/month/year with slashes)
            '%m-%d-%Y',               # Example: 09-23-2024 (US month-day-year)
            '%m/%d/%Y',               # Example: 09/23/2024 (US month/day/year with slashes)
            '%d-%b-%Y',               # Example: 9-Aug-2024 (day-abbreviated month-full year)
            '%d-%B-%Y',               # Example: 9-August-2024 (day-full month-full year)
            '%d-%b-%y',               # Example: 9-Aug-24 (day-abbreviated month-short year)
            '%d-%B-%y',               # Example: 9-August-24 (day-full month-short year)
            '%B %d, %Y',              # Example: August 9, 2024 (full month day, year)
            '%b %d, %Y',              # Example: Aug 9, 2024 (abbreviated month day, year)
            '%d %B %Y',               # Example: 9 August 2024 (day full month full year)
            '%d %b %Y',               # Example: 9 Aug 2024 (day abbreviated month full year)
            '%d %B %y',               # Example: 9 August 24 (day full month short year)
            '%d %b %y',               # Example: 9 Aug 24 (day abbreviated month short year)
            '%m/%d/%y',               # Example: 09/23/24 (US short month/day/year)
            '%b %d %Y',               # Example: Aug 09 2024 (abbreviated month day year without comma)
        ]
        
        for date_format in date_formats:
            try:
                return datetime.strptime(date_str.split('T')[0], date_format).date()
            except ValueError:
                continue  # Try the next format if the current one fails
        
        print(f"Error: No matching format for date: {date_str}")
        return None
    
    return None

conn = getConnection()
if conn:
    try:
        cursor = conn.cursor()
        truncate_query = sql.SQL("TRUNCATE TABLE " + table_name + ";")
        cursor.execute(truncate_query)

        df = pd.read_csv(csv_file)
        df = df.replace({np.nan: ''})
        for index, row in df.iterrows():
            print(str(index+1) + ' out of ' + str(len(df)))

            seq_no_job_code = str(row.get('SeqNo')) + '_' + row.get('JobCode')

            query = sql.SQL("INSERT INTO " + table_name + 
                            """ (seq_no, job_title, job_code, seq_no_job_code, number_of_vacancy, city, state, country, department, client_name, created_date, last_modified_date, created_by, job_status, job_type, application_start_date, time_to_fill, "Designation Title", "Actual Requisition Start Date", "Requisition Activated On", "Requisition Last Approved On", "Requisition Initiated On", "Product/Channel/Platform/Segment", "HRBP Name", "Position Type", "Comments", "HRBP", "Requisition ID- DB", "Legal Entity", "Job Role", "Role Code", "Product Code", "Business Code", "Business", "Job Family", "Job Family Code", "Sub-Job Family", "Sub Job Family Code", "Functional Competence/Skills", "Requisition Raised By - Employee Name", "Requisition Raised By - Employee ID", "Reporting Manager ID", "Reporting Manager", "Position - Replacement Employee ID", "Position - Replacement Employee Name", "Number Of Replacement Positions", "Number Of New Positions", "CTC Range Min", "CTC Range Max", "Requisition Last Approved By", "Requisition Status", "Requested Job TAT", "HRBP Employee ID", "Requisition Hiring Lead", "More Information on the Role (Optional)", "Preferred Company/Industry", "In Take Meeting Notes", "Sub-Business", "Sub-Product/Channel/Platform/Segment", "Sub Sub-Sub-Product/Channel/Platform/Segment", "Designation", "Job Level", "Position Job Level Code", "Employment Type", "Employee ID of Replacement", "Name of Replacement", "Time Type", "Hiring Channel Preference", "Contribution Level", "Roles & Responsibilities", "Job Type", "ResumeStatesCount_PoolCount", "ResumeStatesCount_ScreenCount", "ResumeStatesCount_InterviewCount", "ResumeStatesCount_HireCount", "ResumeStatesCount_OfferCount", "RejectedStatesCount_PoolCount", "RejectedStatesCount_ScreenCount", "RejectedStatesCount_InterviewCount", "RejectedStatesCount_HireCount", "RejectedStatesCount_OfferCount", "refresh_date") 
                        VALUES (%s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	decode(public.encrypt_aes(%s), 'base64'),	decode(public.encrypt_aes(%s), 'base64'),	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s,	 %s);""")
                
            cursor.execute(query, (
                str(row.get('SeqNo')), 
                row.get('JobTitle'), 
                row.get('JobCode'), 
                seq_no_job_code, 
                int(row.get('NumberOfVacancy')) if row.get('NumberOfVacancy') else None, 
                row.get('City'), 
                row.get('State'), 
                row.get('Country'), 
                row.get('Department'), 
                row.get('ClientName'),
                parse_datetime(row.get('CreatedDate')),
                parse_datetime(row.get('LastModifiedDate')),
                row.get('CreatedBy'), 
                row.get('JobStatus'), 
                row.get('JobType'), 
                parse_datetime(row.get('ApplicationStartDate')),
                row.get('TimeToFill'), 
                row.get('AdditionalFields.Designation Title'), 
                parse_datetime(row.get('AdditionalFields.Actual Requisition Start Date')), 
                parse_datetime(row.get('AdditionalFields.Requisition Activated On')),
                parse_datetime(row.get('AdditionalFields.Requisition Last Approved On')), 
                parse_datetime(row.get('AdditionalFields.Requisition Initiated On')), 
                row.get('AdditionalFields.Product/Channel/Platform/Segment'), 
                row.get('AdditionalFields.HRBP Name'), 
                row.get('AdditionalFields.Position Type'), 
                row.get('AdditionalFields.Comments'), 
                row.get('AdditionalFields.HRBP'), 
                row.get('AdditionalFields.Requisition ID- DB'), 
                row.get('AdditionalFields.Legal Entity'), 
                row.get('AdditionalFields.Job Role'), 
                row.get('AdditionalFields.Role Code'), 
                row.get('AdditionalFields.Product Code'), 
                row.get('AdditionalFields.Business Code'), 
                row.get('AdditionalFields.Business'), 
                row.get('AdditionalFields.Job Family'), 
                row.get('AdditionalFields.Job Family Code'), 
                row.get('AdditionalFields.Sub-Job Family'), 
                row.get('AdditionalFields.Sub Job Family Code'), 
                row.get('AdditionalFields.Functional Competence/Skills'), 
                row.get('AdditionalFields.Requisition Raised By - Employee Name'), 
                row.get('AdditionalFields.Requisition Raised By - Employee ID'), 
                row.get('AdditionalFields.Reporting Manager ID'), 
                row.get('AdditionalFields.Reporting Manager'), 
                row.get('AdditionalFields.Position - Replacement Employee ID'), 
                row.get('AdditionalFields.Position - Replacement Employee Name'), 
                int(row.get('AdditionalFields.Number Of Replacement Positions')) if row.get('AdditionalFields.Number Of Replacement Positions') else None,
                int(row.get('AdditionalFields.Number Of New Positions')) if row.get('AdditionalFields.Number Of New Positions') else None,
                row.get('AdditionalFields.CTC Range Min'), 
                row.get('AdditionalFields.CTC Range Max'), 
                row.get('AdditionalFields.Requisition Last Approved By'), 
                row.get('AdditionalFields.Requisition Status'), 
                row.get('AdditionalFields.Requested Job TAT'), 
                row.get('AdditionalFields.HRBP Employee ID'), 
                row.get('AdditionalFields.Requisition Hiring Lead'), 
                row.get('AdditionalFields.More Information on the Role (Optional)'), 
                row.get('AdditionalFields.Preferred Company/Industry'), 
                row.get('AdditionalFields.In Take Meeting Notes'), 
                row.get('AdditionalFields.Sub-Business'), 
                row.get('AdditionalFields.Sub-Product/Channel/Platform/Segment'), 
                row.get('AdditionalFields.Sub Sub-Sub-Product/Channel/Platform/Segment'), 
                row.get('AdditionalFields.Designation'), 
                row.get('AdditionalFields.Job Level'), 
                row.get('AdditionalFields.Position Job Level Code'),
                row.get('AdditionalFields.Employment Type'),
                row.get('AdditionalFields.Employee ID of Replacement'), 
                row.get('AdditionalFields.Name of Replacement'), 
                row.get('AdditionalFields.Time Type'), 
                row.get('AdditionalFields.Hiring Channel Preference'), 
                row.get('AdditionalFields.Contribution Level'),
                row.get('AdditionalFields.Roles & Responsibilities'), 
                row.get('AdditionalFields.Job Type'), 
                row.get('ResumeStatesCount.PoolCount'),
                row.get('ResumeStatesCount.ScreenCount'),
                row.get('ResumeStatesCount.InterviewCount'),
                row.get('ResumeStatesCount.HireCount'),
                row.get('ResumeStatesCount.OfferCount'),
                row.get('RejectedStatesCount.PoolCount'),
                row.get('RejectedStatesCount.ScreenCount'),
                row.get('RejectedStatesCount.InterviewCount'),
                row.get('RejectedStatesCount.HireCount'),
                row.get('RejectedStatesCount.OfferCount'),
                today
            ))
        
        # Commit the transaction
        conn.commit()
        
        print("Data from CSV inserted successfully.")
    
    except Exception as e:
        conn.rollback()
        print(f"An error occurred: {e}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()
else:
    print("Failed to establish connection.")