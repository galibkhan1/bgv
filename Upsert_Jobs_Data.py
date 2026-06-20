import psycopg2
from psycopg2 import OperationalError, sql
import os

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

def upsert_data():
    conn = getConnection()
    if conn:
        cursor = None
        try:
            cursor = conn.cursor()
            query = sql.SQL("""
                INSERT INTO public.turbohire_jobs_data_main (seq_no, job_title, job_code, seq_no_job_code, number_of_vacancy, city, state, country, department, client_name, created_date, last_modified_date, created_by, job_status, job_type, application_start_date, time_to_fill, "Designation Title", "Actual Requisition Start Date", "Requisition Activated On", "Requisition Last Approved On", "Requisition Initiated On", "Product/Channel/Platform/Segment", "HRBP Name", "Position Type", "Comments", "HRBP", "Requisition ID- DB", "Legal Entity", "Job Role", "Role Code", "Product Code", "Business Code", "Business", "Job Family", "Job Family Code", "Sub-Job Family", "Sub Job Family Code", "Functional Competence/Skills", "Requisition Raised By - Employee Name", "Requisition Raised By - Employee ID", "Reporting Manager ID", "Reporting Manager", "Position - Replacement Employee ID", "Position - Replacement Employee Name", "Number Of Replacement Positions", "Number Of New Positions", "CTC Range Min", "CTC Range Max", "Requisition Last Approved By", "Requisition Status", "Requested Job TAT", "HRBP Employee ID", "Requisition Hiring Lead", "More Information on the Role (Optional)", "Preferred Company/Industry", "In Take Meeting Notes", "Sub-Business", "Sub-Product/Channel/Platform/Segment", "Sub Sub-Sub-Product/Channel/Platform/Segment", "Designation", "Job Level", "Position Job Level Code", "Employment Type", "Employee ID of Replacement", "Name of Replacement", "Time Type", "Hiring Channel Preference", "Contribution Level", "Roles & Responsibilities", "Job Type", "ResumeStatesCount_PoolCount", "ResumeStatesCount_ScreenCount", "ResumeStatesCount_InterviewCount", "ResumeStatesCount_HireCount", "ResumeStatesCount_OfferCount", "RejectedStatesCount_PoolCount", "RejectedStatesCount_ScreenCount", "RejectedStatesCount_InterviewCount", "RejectedStatesCount_HireCount", "RejectedStatesCount_OfferCount", refresh_date)
                SELECT DISTINCT * FROM public.turbohire_jobs_data_stg
                ON CONFLICT (seq_no_job_code) DO UPDATE
                SET
                    seq_no = EXCLUDED.seq_no,
                    job_title = EXCLUDED.job_title,
                    job_code = EXCLUDED.job_code,
                    seq_no_job_code = EXCLUDED.seq_no_job_code,
                    number_of_vacancy = EXCLUDED.number_of_vacancy,
                    city = EXCLUDED.city,
                    state = EXCLUDED.state,
                    country = EXCLUDED.country,
                    department = EXCLUDED.department,
                    client_name = EXCLUDED.client_name,
                    created_date = EXCLUDED.created_date,
                    last_modified_date = EXCLUDED.last_modified_date,
                    created_by = EXCLUDED.created_by,
                    job_status = EXCLUDED.job_status,
                    job_type = EXCLUDED.job_type,
                    application_start_date = EXCLUDED.application_start_date,
                    time_to_fill = EXCLUDED.time_to_fill,
                    "Designation Title" = EXCLUDED."Designation Title",
                    "Actual Requisition Start Date" = EXCLUDED."Actual Requisition Start Date",
                    "Requisition Activated On" = EXCLUDED."Requisition Activated On",
                    "Requisition Last Approved On" = EXCLUDED."Requisition Last Approved On",
                    "Requisition Initiated On" = EXCLUDED."Requisition Initiated On",
                    "Product/Channel/Platform/Segment" = EXCLUDED."Product/Channel/Platform/Segment",
                    "HRBP Name" = EXCLUDED."HRBP Name",
                    "Position Type" = EXCLUDED."Position Type",
                    "Comments" = EXCLUDED."Comments",
                    "HRBP" = EXCLUDED."HRBP",
                    "Requisition ID- DB" = EXCLUDED."Requisition ID- DB",
                    "Legal Entity" = EXCLUDED."Legal Entity",
                    "Job Role" = EXCLUDED."Job Role",
                    "Role Code" = EXCLUDED."Role Code",
                    "Product Code" = EXCLUDED."Product Code",
                    "Business Code" = EXCLUDED."Business Code",
                    "Business" = EXCLUDED."Business",
                    "Job Family" = EXCLUDED."Job Family",
                    "Job Family Code" = EXCLUDED."Job Family Code",
                    "Sub-Job Family" = EXCLUDED."Sub-Job Family",
                    "Sub Job Family Code" = EXCLUDED."Sub Job Family Code",
                    "Functional Competence/Skills" = EXCLUDED."Functional Competence/Skills",
                    "Requisition Raised By - Employee Name" = EXCLUDED."Requisition Raised By - Employee Name",
                    "Requisition Raised By - Employee ID" = EXCLUDED."Requisition Raised By - Employee ID",
                    "Reporting Manager ID" = EXCLUDED."Reporting Manager ID",
                    "Reporting Manager" = EXCLUDED."Reporting Manager",
                    "Position - Replacement Employee ID" = EXCLUDED."Position - Replacement Employee ID",
                    "Position - Replacement Employee Name" = EXCLUDED."Position - Replacement Employee Name",
                    "Number Of Replacement Positions" = EXCLUDED."Number Of Replacement Positions",
                    "Number Of New Positions" = EXCLUDED."Number Of New Positions",
                    "CTC Range Min" = EXCLUDED."CTC Range Min",
                    "CTC Range Max" = EXCLUDED."CTC Range Max",
                    "Requisition Last Approved By" = EXCLUDED."Requisition Last Approved By",
                    "Requisition Status" = EXCLUDED."Requisition Status",
                    "Requested Job TAT" = EXCLUDED."Requested Job TAT",
                    "HRBP Employee ID" = EXCLUDED."HRBP Employee ID",
                    "Requisition Hiring Lead" = EXCLUDED."Requisition Hiring Lead",
                    "More Information on the Role (Optional)" = EXCLUDED."More Information on the Role (Optional)",
                    "Preferred Company/Industry" = EXCLUDED."Preferred Company/Industry",
                    "In Take Meeting Notes" = EXCLUDED."In Take Meeting Notes",
                    "Sub-Business" = EXCLUDED."Sub-Business",
                    "Sub-Product/Channel/Platform/Segment" = EXCLUDED."Sub-Product/Channel/Platform/Segment",
                    "Sub Sub-Sub-Product/Channel/Platform/Segment" = EXCLUDED."Sub Sub-Sub-Product/Channel/Platform/Segment",
                    "Designation" = EXCLUDED."Designation",
                    "Job Level" = EXCLUDED."Job Level",
                    "Position Job Level Code" = EXCLUDED."Position Job Level Code",
                    "Employment Type" = EXCLUDED."Employment Type",
                    "Employee ID of Replacement" = EXCLUDED."Employee ID of Replacement",
                    "Name of Replacement" = EXCLUDED."Name of Replacement",
                    "Time Type" = EXCLUDED."Time Type",
                    "Hiring Channel Preference" = EXCLUDED."Hiring Channel Preference",
                    "Contribution Level" = EXCLUDED."Contribution Level",
                    "Roles & Responsibilities" = EXCLUDED."Roles & Responsibilities",
                    "Job Type" = EXCLUDED."Job Type",
                    "ResumeStatesCount_PoolCount" = EXCLUDED."ResumeStatesCount_PoolCount",
                    "ResumeStatesCount_ScreenCount" = EXCLUDED."ResumeStatesCount_ScreenCount",
                    "ResumeStatesCount_InterviewCount" = EXCLUDED."ResumeStatesCount_InterviewCount",
                    "ResumeStatesCount_HireCount" = EXCLUDED."ResumeStatesCount_HireCount",
                    "ResumeStatesCount_OfferCount" = EXCLUDED."ResumeStatesCount_OfferCount",
                    "RejectedStatesCount_PoolCount" = EXCLUDED."RejectedStatesCount_PoolCount",
                    "RejectedStatesCount_ScreenCount" = EXCLUDED."RejectedStatesCount_ScreenCount",
                    "RejectedStatesCount_InterviewCount" = EXCLUDED."RejectedStatesCount_InterviewCount",
                    "RejectedStatesCount_HireCount" = EXCLUDED."RejectedStatesCount_HireCount",
                    "RejectedStatesCount_OfferCount" = EXCLUDED."RejectedStatesCount_OfferCount",
                    "refresh_date" = EXCLUDED."refresh_date"
            """)

            cursor.execute(query)
            conn.commit()
            print("Upsert operation completed successfully.")
        except Exception as e:
            print(f"An error occurred: {e}")
            conn.rollback()
            raise
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()
    else:
        print("Failed to establish connection.")
        
upsert_data()