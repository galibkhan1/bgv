import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from airflow import DAG
from airflow.providers.standard.operators.bash import BashOperator
from airflow.providers.standard.operators.python import PythonOperator
from airflow.task.trigger_rule import TriggerRule
from datetime import timedelta , datetime
import os

def send_failure_alert(*context):
    smtp_server = 'email-smtp.eu-central-1.amazonaws.com'
    smtp_port = 587
    smtp_user = os.getenv('smtp_username')
    smtp_pass = os.getenv('smtp_password')
    
    SENDER_EMAIL_DISPLAY_NAME = "Meganta IQ"
    SENDER_EMAIL_ADDRESS_ONLY = "noreply@meganta.iq.yo-digital.com"

    # Email details
    FULL_SENDER = f'"{SENDER_EMAIL_DISPLAY_NAME}" <{SENDER_EMAIL_ADDRESS_ONLY}>'
    to_email = ['ganesh.varshney.ext@telekom-digital.com', 'daksh.sahni.ext@telekom-digital.com', 'ankit.kumar1@telekom-digital.com']
    
    # Retrieve the failed task ID from XCom
    task_instance = context['task_instance']
    failed_task_id = task_instance.xcom_pull(key='failed_task_id', task_ids=None)

    subject = 'DAG Failed Alert'
    body = f"DAG Failed:\n\nFailed Task ID: {failed_task_id}\nDAG ID: {context['dag'].dag_id}\nExecution Date: {context['execution_date']}"

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = FULL_SENDER
    msg['To'] = ', '.join(to_email)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(FULL_SENDER, to_email, msg.as_string())
            server.quit()
            print("Email sent successfully!")

    except Exception as e:
        print(f"Failed to send email: {e}")

def failure_callback(context):
    task_instance = context['task_instance']
    task_instance.xcom_push(key='failed_task_id', value=task_instance.task_id)
    send_failure_alert(context)

default_args = {
    'owner': 'admin',
    'depends_on_past': False,
    'start_date': datetime.today() - timedelta(days =1),
    'retries': 1,
    'retry_delay': timedelta(minutes=3),
    'execution_timeout': timedelta(minutes=30),
    'dagrun_timeout': timedelta(hours = 1),
    'on_failure_callback': failure_callback
}

dag = DAG(
    'Turbothire_Offer_Letter',
    default_args=default_args,
    description='Offer Letter DAG',
    schedule='25 1 * * *'
)

# Define tasks
task1 = BashOperator(
    task_id='fetch_and_create_csv',
    bash_command='sudo python3 /home/ec2-user/PythonCodes/Turbohire/Offer/OfferLetterData.py',
    dag=dag
)

task2 = BashOperator(
    task_id='insert_data_in_stg',
    bash_command='sudo python3 /home/ec2-user/PythonCodes/Turbohire/Offer/Insert_OfferLetterData.py',
    dag=dag
)

task3 = BashOperator(
    task_id='upsert_data_in_main',
    bash_command='sudo python3 /home/ec2-user/PythonCodes/Turbohire/Offer/Upsert_OfferLetterData_Main.py',
    dag=dag
)

failure_alert = PythonOperator(
    task_id='send_failure_alert',
    python_callable=send_failure_alert,
    trigger_rule=TriggerRule.ONE_FAILED,
    dag=dag
)

# Set task dependencies
task1 >> task2 >> task3
[task1, task2, task3] >> failure_alert