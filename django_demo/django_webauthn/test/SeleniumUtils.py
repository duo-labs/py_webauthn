import os
import re
from selenium import webdriver
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait

IP="https://localhost:8443"

class SeleniumHelper(object):

    def cfg(self):
        options = webdriver.ChromeOptions()
        options.add_argument('--ignore-ssl-errors=yes')
        options.add_argument('--ignore-certificate-errors')
        self.driver = webdriver.Chrome(options=options)
        self.IP=IP
        self.testuser = os.getenv("TESTUSER")

    def is_element_present(self, params):
        WebDriverWait(self.driver, 30).until(
              EC.presence_of_element_located((By.XPATH,params['xpath'])))
        try: self.driver.find_element_by_xpath(params['xpath'])
        except NoSuchElementException, e: assert False
        assert True

    def open_n_tst_title (self, params):
        self.driver.get(params['url'])
        self.driver.maximize_window()
        WebDriverWait(self.driver, 30).until(
              EC.presence_of_element_located((By.ID,'page_loaded')))
        assert re.search(params['title'], self.driver.title, re.I)
