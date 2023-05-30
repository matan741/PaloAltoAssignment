import logging
import sys
import re
import time
import multiprocessing

import pytz
import pandas
import pandas as pd
import warnings
import matplotlib
import plotly.express as px
import matplotlib.pyplot as plt
import seaborn as sns
import threading

from multiprocessing import Process
from threading import Thread
from datetime import datetime


log_source_time_list = []

dashbored3_log_source_time_list = []
dashbored3_http_response_list = []
dashbored3_ip_address_list = []

ip_address_list = []
http_response_message_list = []
http_response_list = []
http_request_method_list = []
http_request_endpoint_list = []
dasbored_reponse_meesage = []
malicious_script_list = []


def create_logger():
    logger = logging.getLogger('logger')
    formatter = logging.Formatter(
        '%(asctime)s (%(filename)s:%(lineno)d %(threadName)s) %(levelname)s: %(message)s'
    )

    console_output_handler = logging.StreamHandler(sys.stdout)
    console_output_handler.setFormatter(formatter)
    logger.addHandler(console_output_handler)

    file_output_handler = logging.FileHandler("./logger.log")
    file_output_handler.setFormatter(formatter)
    logger.addHandler(file_output_handler)
    logger.setLevel(logging.DEBUG)
    return logger


def rule_1(ip_address_list, http_response_list,malicious_script_list,log_source_time_list):
    if malicious_script_list[-1]:
        if len(ip_address_list) >= 3 and ip_address_list[-1] == ip_address_list[-2] and ip_address_list[-1] == ip_address_list[-3]:
            if http_response_list[-1] != 200 and http_response_list[-2] != 200 and http_response_list[-3] != 200:
                if len(log_source_time_list) >= 4 and log_source_time_list[-1] != log_source_time_list[-4]:
                    print("------------------------------------------------------------------")
                    print("Alert Occur - Rule name: ")
                    print("Time: ", log_source_time_list[-1])
                    print("Suspicious API Request: ", malicious_script_list[-1])
                    print("HTTP Respnse: ", http_response_list[-1])
                    return


def dashbored1_visualization_bar_plot(dashbored1):
    dashbored1 = dashbored1[dashbored1['Source Address'] != 'None']
    plt.figure(figsize=(22, 8))
    sns.countplot(x='Source Address', data=dashbored1)
    plt.title('Source IP interaction with Apachi server ')
    plt.xlabel('')
    plt.ylabel('Count')
    plt.savefig('Bar Plot.png')
    plt.close()


def dashbored2_visualization_pie_chart(dashbored2):

    dashbored2 = dashbored2[dashbored2['dasbored_reponse_meesage'] != 'None']
    labels = dashbored2['dasbored_reponse_meesage'].value_counts().index.tolist()
    sizes = dashbored2['dasbored_reponse_meesage'].value_counts().tolist()
    colors = ['blue', 'green', 'yellow', 'red', 'orange', 'purple','brown']

    plt.figure(figsize=(25, 15))
    plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', textprops={'fontsize': 20})
    plt.title('')
    plt.axis('equal')  # Equal aspect ratio ensures that the pie is drawn as a circle.
    plt.savefig('Server Response Pie Chart.png')
    plt.close()


def dashbored3_visualization(dashbored3):
    plt.figure(figsize=(32, 17))
    plt.scatter(dashbored3['Source Address'], dashbored3['Malicious Requests'])
    plt.tick_params(axis='x', labelsize=15)
    plt.tick_params(axis='y', labelsize=12)
    plt.xlabel('Source Address', fontsize=12)
    plt.ylabel('Malicious Or Not Valid Requests', fontsize=12)
    plt.title('Correlation between Source IP and Malicious Requests')
    plt.savefig('Scatter chart')
    plt.close()


def convert_to_common_format(log_time, current_format):
    current_datetime = datetime.strptime(log_time, current_format)

    desired_format = "%Y-%m-%d %H:%M:%S"

    converted_time = current_datetime.strftime(desired_format)

    return converted_time


def identify_time_format(log_source_time):
    formats = [
        "%d/%b/%Y:%H:%M:%S",
        "%a %b %d %H:%M:%S.%f %Y",
        "%y:%m:%d %H:%M:%S",
        "%Y %H:%M:%S",
        "%a %b %d %H:%M:%S.%f %Y",
        "%H:%M:%S",
    ]

    for fmt in formats:
        try:
            datetime.strptime(log_source_time[0], fmt)

            return fmt
        except ValueError:
            pass

    return None


def parse_logs_into_table(log_file, logger, line_count):

    ip_pattern = r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    time_pattern = r"\d{1,2}\/[A-Za-z]+\/\d{1,4}:\d{1,2}:\d{1,2}:\d{1,4}|[A-Za-z]{3} [A-Za-z]{3} \d{2} \d{2}:\d{2}:\d{2}.\d{6} \d{4}|\d{2}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}|\d{4} \d{2}:\d{2}:\d{2}|\d{2}:\d{2}:\d{2}"
    http_response_pattern = r"\d\"\s(\d{1,3})"
    http_request_method_pattern = r"(POST|GET|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH+)"
    http_request_endpoint_pattern = r"\s\"[POST|GET|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH]+\s([^\"]+)|(C:[^\s]+)|\s\[[a-z]([^]]+)]|source\":\"([^,]+)"

    log_row = 1

    for log in log_file:
        http_response_message = None
        ip_address = re.search(ip_pattern, log)
        log_source_time = re.search(time_pattern, log)
        http_response = re.search(http_response_pattern, log)
        http_request_method = re.search(http_request_method_pattern, log)
        http_request_endpoint = re.search(http_request_endpoint_pattern, log)

        if log_source_time is not None:
            log_source_time_format = identify_time_format(log_source_time)
            updated_time_format = convert_to_common_format(log_source_time.group(), log_source_time_format)
            log_source_time_list.append(updated_time_format)
        else:
            log_source_time = "None"
            log_source_time_list.append(log_source_time)

        if ip_address is not None:
            ip_address_list.append(ip_address.group())
        else:
            ip_address = "None"
            ip_address_list.append(ip_address)

        if http_response is not None:
            if 199 >= int(http_response[1]) >= 100:
                http_response_message = "Informational"
            elif 299 >= int(http_response[1]) >= 200:
                http_response_message = "Successful"
                dasbored_reponse_meesage.append(http_response_message)
            elif 399 >= int(http_response[1]) >= 300:
                http_response_message = "Redirection"
                dasbored_reponse_meesage.append(http_response_message)
            elif 499 >= int(http_response[1]) >= 400:
                http_response_message = "Client error"
                dasbored_reponse_meesage.append(http_response_message)

            http_response_list.append(http_response.group(1))
            http_response_message_list.append(http_response_message)

        else:
            server_info_pattern = r'[a-zA-Z]+\d{5}:\s([^$]+)'
            server_info = re.search(server_info_pattern, log)
            if server_info is not None and http_request_endpoint is not None:
                http_response_message = http_request_endpoint[0].split(":")

                http_response_message_list.append(server_info.group(1)[:-1])
                http_response_list.append(http_response_message[1][:-1])
                if "error" in http_response_message[1][:-1]:
                    dasbored_reponse_meesage.append("Server Error")
                else:
                    dasbored_reponse_meesage.append(http_response_message[1][:-1])

            else:
                http_response = "None"
                http_response_message = "None"
                http_response_list.append(http_response)
                http_response_message_list.append(http_response_message)
                dasbored_reponse_meesage.append(http_response)

        if http_request_method is not None:
            http_request_method_list.append(http_request_method.group())

        else:
            http_request_method = "None"
            http_request_method_list.append(http_request_method)

        if http_request_endpoint is not None:
            if http_request_endpoint[1] is not None:
                http_request_endpoint_list.append(http_request_endpoint.group(1)[:-8])

                malicious_script_patterns = r'/%3C([^\s]+)'
                malicious_script = re.search(malicious_script_patterns, http_request_endpoint.group(1))
                if malicious_script is not None:
                    malicious_script_list.append(malicious_script[0])
                    dashbored3_ip_address_list.append(ip_address.group())
                    dashbored3_log_source_time_list.append(updated_time_format)
                    dashbored3_http_response_list.append(http_response.group(1))

                elif len(http_request_endpoint.group(1)) < 20:
                    malicious_script_list.append(http_request_endpoint.group(1)[:-8])
                    dashbored3_ip_address_list.append(ip_address.group())
                    dashbored3_log_source_time_list.append(updated_time_format)
                    dashbored3_http_response_list.append(http_response.group(1))

            else:
                http_request_endpoint_list.append(http_request_endpoint.group(0))
        else:
            http_request_endpoint = "None"
            http_request_endpoint_list.append(http_request_endpoint)

        warnings.simplefilter(action='ignore', category=FutureWarning)

        df = pd.DataFrame(columns=["Log Source Time", "Source Address", "HTTP Request", "HTTP Response", "Endpoint / Path", "Server Response"])

        pd.set_option('display.max_rows', None)
        pd.set_option('display.max_columns', None)
        pd.set_option('display.max_colwidth', -1)
        pd.set_option('colheader_justify', 'center')
        pandas.set_option('display.width', 400)

        df["Log Source Time"] = log_source_time_list
        df["Source Address"] = ip_address_list
        df["HTTP Request"] = http_request_method_list
        df["Endpoint / Path"] = http_request_endpoint_list
        df["HTTP Response"] = http_response_list
        df["Server Response"] = http_response_message_list

        log_row += 1
        if log_row == line_count:
            print('\n', df)

            dashbored1 = pd.DataFrame(columns=["Source Address"])
            dashbored1["Source Address"] = ip_address_list

            dashbored2 = pd.DataFrame(columns=["dasbored_reponse_meesage"])
            dashbored2["dasbored_reponse_meesage"] = dasbored_reponse_meesage

            dashbored3 = pd.DataFrame(columns=["Source Address", "Malicious Requests"])
            dashbored3["Source Address"] = dashbored3_ip_address_list
            dashbored3["Malicious Requests"] = malicious_script_list
            dashbored3["Time"] = dashbored3_log_source_time_list
            dashbored3["HTTP Response"] = dashbored3_http_response_list
            #print('\n', dashbored3)
            return dashbored1, dashbored2, dashbored3, log_row


if __name__ == "__main__":
    logger = create_logger()
    system_is_active = True
    log_row = 1
    while system_is_active:

        with open("./apache_logs_to_parse.log", "r") as log_file:
            line_count = sum(1 for _ in log_file)

        log_file = open("./apache_logs_to_parse.log", "r")

        if log_row != line_count:
            print('\n', "Starting to read log file")
            dashbored1,dashbored2, dashbored3, log_row = parse_logs_into_table(log_file, logger, line_count)
            print("Read all line in the files..")

            thread1 = multiprocessing.Process(target=dashbored2_visualization_pie_chart, args=(dashbored2,))
            thread2 = multiprocessing.Process(target=dashbored1_visualization_bar_plot, args=(dashbored1,))
            thread3 = multiprocessing.Process(target=dashbored3_visualization, args=(dashbored3,))

            thread1.start()
            thread2.start()
            thread3.start()

            thread1.join()
            thread2.join()
            thread3.join()

        else:
            print("There are no more lines to read in the file..")
            time.sleep(10)
