import time
import datetime
import random
import json
import requests

from ThreadWithReturnValue import ThreadWithReturnValue
from threading import Thread


def wait_for_two_hours_divided_by_5_without_reminder():
    now = datetime.datetime.now()
    print("Now:" + now.strftime("%H:%M:%S"))

    now_time_in_seconds = now.minute * 60 + now.second

    five_minutes_in_seconds = 5 * 60

    reminder_from_5m = now_time_in_seconds % five_minutes_in_seconds

    if reminder_from_5m != 0:
        quotient_from_5m = int(now_time_in_seconds / five_minutes_in_seconds)
        seconds_left_to_5m_time = (quotient_from_5m + 1) * five_minutes_in_seconds - now_time_in_seconds
        if seconds_left_to_5m_time > 0:
            print("Sleep for:" + str((seconds_left_to_5m_time + 3600) / 60) + " minutes...")
            time.sleep(seconds_left_to_5m_time + 3600)
            print("Woke up!" + '\n')
            print("Woke up!" + '\n')
            print("Woke up!" + '\n')
        else:
            print("Sleep for:" + str((seconds_left_to_5m_time + 3600) / 60) + " minutes...")
            time.sleep(seconds_left_to_5m_time + 3600)
            print("Woke up!" + '\n')


class EventGenerator(Thread):
    def __init__(self, city, country, coordinates, ATM_id, transaction_id, customer_name, customer_id, credit_card_id, amount, customer_profile):
        Thread.__init__(self)
        self.city = city
        self.country = country
        self.coordinates = coordinates
        self.ATM_id = ATM_id
        self.transaction_id = transaction_id
        self.customer_name = customer_name
        self.customer_id = customer_id
        self.credit_card_id = credit_card_id
        self.amount = amount
        self.customer_profile = customer_profile
        self.splunk_host = '127.0.0.1'
        self.hec_port = '8088'
        self.hec_token = 'a1536155-eb0c-4e56-8ccf-37b9baf95dae'
        self.hec_url = f'http://{self.splunk_host}:{self.hec_port}/services/collector'
        self.headers = {
            'Authorization': f'Splunk {self.hec_token}',
            'Content-Type': 'application/json'
        }

    def format_log_data(self, rand_forrmated_log, formatted_log_1):
        format_log_data = {
            "event": "Credit card withrow notice 2",
            "source": "bit",
            "sourcetype": "json",
            "index": "banktim",
            "fields":
                {
                    "city": rand_forrmated_log['city'],
                    "country": rand_forrmated_log['country'],
                    "transaction_id": rand_forrmated_log['transaction_id'],
                    "customer_name": self.customer_name,
                    "customer_id": self.customer_id,
                    "credit_card_id": self.credit_card_id,
                    "amount": rand_forrmated_log['amount'],
                }
        }

        format_log_data_1 = {
            "event": "Credit card withrow notice 2",
            "source": "banktim",
            "sourcetype": "json",
            "index": "banktim",
            "fields":
                {
                    "city": formatted_log_1['city'],
                    "country": formatted_log_1['country'],
                    "source_ip": formatted_log_1['source_ip'],
                    "ATM_id": formatted_log_1['ATM_id'],
                    "transaction_id": formatted_log_1['transaction_id'],
                    "customer_name": self.customer_name,
                    "customer_id": self.customer_id,
                    "credit_card_id": self.credit_card_id,
                    "amount": formatted_log_1['amount'],
                }
        }
        return format_log_data, format_log_data_1

    def random_values_to_log(self):

        if "Cautious" in self.customer_profile:
            random_number = random.randint(100000, 999999)
            customer_profile = [92, 4, 1, 0, 1, 1, 0, 1]

            abnormal_amounts = [3000, 3600, 7000, 8000, 6000]
            abnormal_amounts_odds = [20, 20, 20, 20, 20]
            chosen_index = random.choices(range(len(abnormal_amounts)), weights=abnormal_amounts_odds)[0]

            amounts = [100, 200, 500, 1000, abnormal_amounts[chosen_index]]
            amounts_odss = [33, 20, 15, 10, 5]
            chosen_index = random.choices(range(len(amounts)), weights=amounts_odss)[0]
            amount = amounts[chosen_index]

        elif "Normal" in self.customer_profile:
            random_number = random.randint(100000, 999999)
            customer_profile = [90, 1, 6, 1, 1, 1, 1, 1]

            abnormal_amounts = [3000, 3600, 7000, 8000, 6000]
            abnormal_amounts_odds = [20, 20, 20, 20, 20]
            chosen_index = random.choices(range(len(abnormal_amounts)), weights=abnormal_amounts_odds)[0]

            amounts = [100, 200, 500, 1000, abnormal_amounts[chosen_index]]
            amounts_odss = [33, 20, 15, 10, 5]
            chosen_index = random.choices(range(len(amounts)), weights=amounts_odss)[0]
            amount = amounts[chosen_index]

        else:
            random_number = random.randint(100000, 999999)
            customer_profile = [85, 2, 3, 3, 3, 3, 2, 2]

            abnormal_amounts = [3000, 3600, 7000, 8000, 6000]
            abnormal_amounts_odds = [20, 20, 20, 20, 20]
            chosen_index = random.choices(range(len(abnormal_amounts)), weights=abnormal_amounts_odds)[0]

            amounts = [100, 200, 500, 1000, abnormal_amounts[chosen_index]]

            amounts_odss = [33, 20, 15, 10, 5]
            chosen_index = random.choices(range(len(amounts)), weights=amounts_odss)[0]
            amount = amounts[chosen_index]



        return random_number, customer_profile, amount

    def generate_random_values(self):

        rand_transaction_id, customer_profile, amount = self.random_values_to_log()

        log_list_bit = [
            {'city': 'Rehovot', 'country': 'Israel', 'transaction_id': rand_transaction_id, 'amount': 3200},
            {'city': 'Rishon LeZion', 'country': 'Israel', 'transaction_id': rand_transaction_id, 'amount': 3300},
            {'city': 'Eilat', 'country': 'Israel', 'transaction_id': rand_transaction_id, 'amount': 3400},
            {'city': 'New York', 'country': 'USA', 'transaction_id': rand_transaction_id, 'amount': 3500},
            {'city': 'Beijing', 'country': 'China', 'transaction_id': rand_transaction_id, 'amount': 2200},
            {'city': 'Maraba', 'country': 'Brazil', 'transaction_id': rand_transaction_id, 'amount': 3600},
            {'city': 'Berlin', 'country': 'Germany', 'transaction_id': rand_transaction_id, 'amount': 3600},
            {'city': 'Moscow', 'country': 'Russia', 'transaction_id': rand_transaction_id, 'amount': 3600},

        ]
        log_list = [
            {'city': 'Rehovot', 'country': 'Israel', 'source_ip': '62.0.72.3', 'ATM_id': '7411', 'transaction_id': rand_transaction_id, 'amount': amount},
            {'city': 'Rishon LeZion', 'country': 'Israel', 'source_ip': '46.120.63.255', 'ATM_id': '6155', 'transaction_id': rand_transaction_id, 'amount': amount},
            {'city': 'Eilat', 'country': 'Israel', 'source_ip': '213.57.139.118', 'ATM_id': '3325', 'transaction_id': rand_transaction_id, 'amount': amount},
            {'city': 'New York', 'country': 'USA', 'source_ip': '181.177.81.214', 'ATM_id': '4536', 'transaction_id': rand_transaction_id, 'amount': amount},
            {'city': 'Beijing', 'country': 'China', 'source_ip': '39.97.117.59', 'ATM_id': '6155', 'transaction_id': rand_transaction_id, 'amount': amount},
            {'city': 'Maraba', 'country': 'Brazil', 'source_ip': '131.255.225.177', 'ATM_id': '8796', 'transaction_id': rand_transaction_id, 'amount': amount},
            {'city': 'Berlin', 'country': 'Germany', 'source_ip': '196.196.68.171', 'ATM_id': '7855', 'transaction_id': rand_transaction_id, 'amount': amount},
            {'city': 'Moscow', 'country': 'Russia', 'source_ip': '185.94.111.1', 'ATM_id': '6546', 'transaction_id': rand_transaction_id, 'amount': amount},
        ]

        chosen_index = random.choices(range(len(log_list_bit)), weights=customer_profile)[0]
        chosen_index_1 = random.choices(range(len(log_list)), weights=customer_profile)[0]



        log_list_bit[chosen_index]["transaction_id"] = rand_transaction_id
        log_list[chosen_index_1]["transaction_id"] = rand_transaction_id

        return log_list_bit[chosen_index], log_list[chosen_index_1]

    def run(self):

            rand_forrmated_log, rand_forrmated_log_1 = self.generate_random_values()
            formatted_log, formatted_log_1 = self.format_log_data(rand_forrmated_log, rand_forrmated_log_1)
            log_to_splunk = json.dumps(formatted_log)
            log_to_splunk_1 = json.dumps(formatted_log_1)

            response = requests.post(self.hec_url, data=log_to_splunk, headers=self.headers)
            response_1 = requests.post(self.hec_url, data=log_to_splunk_1, headers=self.headers)

            if response.status_code == 200 and response_1.status_code == 200:
                print()
                print('Log data sent successfully to Splunk.')
                print('\n', 'Log Data: ', log_to_splunk_1)
            else:
                print('Failed to send log data to Splunk.')
                print('Response:', response.text)


if __name__ == "__main__":
    while True:

        eitan_customer = EventGenerator(city=None, country=None, coordinates=None, ATM_id=None, transaction_id=None, customer_name="Eitan", customer_id=205658421, credit_card_id=1234212521422152, amount=0, customer_profile="Cautious")
        shir_customer = EventGenerator(city=None, country=None, coordinates=None, ATM_id=None, transaction_id=None, customer_name="Shir", customer_id=41657736, credit_card_id=546453452178678, amount=0, customer_profile="Normal")
        matan_customer = EventGenerator(city=None, country=None, coordinates=None, ATM_id=None, transaction_id=None, customer_name="Matan", customer_id=305727536, credit_card_id=98752454645324, amount=0, customer_profile="Risky")

        eitan_customer.start()
        matan_customer.start()
        shir_customer.start()

        eitan_customer.join()
        matan_customer.join()
        shir_customer.join()

        time.sleep(900)
