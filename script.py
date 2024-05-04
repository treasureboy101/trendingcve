from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import Select
from selenium.webdriver.chrome.options import Options as ChromeOptions
import time
import requests
from datetime import datetime, timedelta
import json
from dotenv import load_dotenv
import os


load_dotenv()
GH_TOKEN = os.getenv("GH_TOKEN")
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")

def yesterday():
    yesterday = datetime.now() - timedelta(days=1)
    formatted_date = yesterday.strftime("%d %b %Y")
    return [f'{formatted_date}']

def lastweek():
    today = datetime.today()
    last_week_date = today - timedelta(weeks=1)
    dates_range = []
    current_date = last_week_date
    while current_date <= today:
        formatted_date = current_date.strftime("%d %b %Y")
        dates_range.append(formatted_date)
        current_date += timedelta(days=1)
    return dates_range

def lastmonth():
    today = datetime.today()
    last_month_date = today.replace(day=1) - timedelta(days=1)
    dates_range = []
    current_date = last_month_date
    while current_date <= today:
        formatted_date = current_date.strftime("%d %b %Y")
        dates_range.append(formatted_date)
        current_date += timedelta(days=1)
    return dates_range

def extract_cve_data(driver, time_period, api_key):
    print(f"Extracting CVE data for {time_period}...")
    select_element = driver.find_element(By.NAME, 'timePeriod')
    select = Select(select_element)
    select.select_by_visible_text(time_period)
    time.sleep(10)
    if time_period=="1 day":
            timea = yesterday()
    elif time_period=="1 week":
            timea = lastweek()
    elif time_period=="1 month":
            timea = lastmonth()
    cve_data = []
    trend_id = 0
    cve_elements = driver.find_elements(By.XPATH, "//a[contains(@class, 'hover:underline') and contains(text(), 'CVE')]")
    for cve_element in cve_elements:
        cve_text = cve_element.text
        audience_element = cve_element.find_element(By.XPATH, "parent::*/..//span[contains(@class, 'text-md')]")
        audience_count = str(audience_element.text.replace(',', ''))
        parent_element = audience_element.find_element(By.XPATH, "parent::div")
        siblings = parent_element.find_elements(By.XPATH, "following-sibling::div")
        post_count = str(siblings[0].find_element(By.XPATH, ".//span[contains(@class, 'text-md')]").text.replace(',', ''))
        repost_count_text = siblings[1].find_element(By.XPATH, ".//span[contains(@class, 'text-md')]").text.replace(',', '')
        repost_count = str(repost_count_text) if repost_count_text.isdigit() else None
        security_vendor = security_vendor_count(cve_text,timea)
        gh_count = github_count(cve_text,timea)
        google_search_results = google_count(api_key, f"'{cve_text}'",time_period)
        cve_data.append({
            "id": trend_id,
            "cve": cve_text,
            "audience_count": audience_count,
            "post_count": post_count,
            "repost_count": repost_count,
            "google_search_results": google_search_results,
            "security_vendor_count": security_vendor,
            "github_count": gh_count,
            "cve_time_period": time_period
        })
        trend_id+=1
    print(f"CVE data extracted for {time_period}.")
    return cve_data
        
def security_vendor_count(cve,timea):
    url = f"http://35.184.175.243/json?query={cve}&time={timea}"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        total_results = len(data)
        return int(total_results)
    else:
        print("Error:", response.status_code)
        return None

def google_count(api_key, query, timePeriod):
    cse_id = "d4217266cb05048c7"
    url = "https://www.googleapis.com/customsearch/v1"
    if timePeriod == "1 day":
        timeRestrict = "d1"
    elif timePeriod == "1 week":
        timeRestrict = "w1"
    elif timePeriod == "1 month":
        timeRestrict = "m1"
    params = {
        "key": api_key,
        "cx": cse_id,
        "q": query,
        "dateRestrict" : timeRestrict
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        data = response.json()
        total_results = data.get("searchInformation", {}).get("totalResults", 0)
        return int(total_results)
    else:
        print("Error:", response.status_code)
        return None

def github_count(cve,timea):
    url = "https://api.github.com/search/repositories"
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "Authorization": f"{GH_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28"
    }
    params = {
        "q": f"{cve}"
    }
    response = requests.get(url, headers=headers, params=params)
    updated_repos_count = 0
    if response.status_code == 200:
        response = response.json()
        for repo in response["items"]:
            updated_at = datetime.strptime(repo["updated_at"], "%Y-%m-%dT%H:%M:%SZ").strftime("%d %b %Y")
            if updated_at in timea:
                updated_repos_count += 1
    else:
        print("Github api cooldown ignore this error")
        time.sleep(30)
        response = requests.get(url, headers=headers, params=params)
        updated_repos_count = 0
        if response.status_code == 200:
            response = response.json()
            for repo in response["items"]:
                updated_at = datetime.strptime(repo["updated_at"], "%Y-%m-%dT%H:%M:%SZ").strftime("%d %b %Y")
                if updated_at in timea:
                    updated_repos_count += 1

    return updated_repos_count

def generate_json():
    print("Starting the process...")
    api_key = F"{GOOGLE_API_KEY}"
    choptions = ChromeOptions()
    choptions.add_argument("--window-size=1920,1080")
    choptions.add_argument("--headless")
    url = "https://www.cveshield.com/"
    driver = webdriver.Chrome(options=choptions)
    driver.get(url)
    time.sleep(10)
  
    cve_data_1_day = extract_cve_data(driver, "1 day", api_key)
    cve_data_1_week = extract_cve_data(driver, "1 week", api_key)
    cve_data_1_month = extract_cve_data(driver, "1 month", api_key)

    driver.quit()

    json_data = {
        "1_day": cve_data_1_day,
        "1_week": cve_data_1_week,
        "1_month": cve_data_1_month
    }

    with open("trending.json", "w") as json_file:
        json.dump(json_data, json_file, indent=4)
    print("JSON data saved to trending.json.")
    print("Process completed.")

if __name__ == "__main__":
    generate_json()
