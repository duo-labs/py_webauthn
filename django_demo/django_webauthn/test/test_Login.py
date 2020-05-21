#!/usr/bin/python 

import re
import sys
import time
from SeleniumUtils import SeleniumHelper

class testLogin(SeleniumHelper):

    def setUp(self):
        self.cfg()
        self.url=self.IP+'/account/login'

    def test01_login(self):
        """
           test login screen
        """
        self.open_n_tst_title({'url': self.url, 'title': 'Secure Login'} )
        xpath = '//*[@id="id_auth-username"]'
        self.is_element_present({ 'xpath': xpath})
        elem =  self.driver.find_element_by_xpath(xpath)

        # clear username field and click login button
        self.driver.execute_script("$('input#id_auth-username').val('');")
        self.driver.find_element_by_xpath('//button[@id="login"]').click()

        print ("Verify that empty username generates 'Invalid username' message...")
        elem2 = self.driver.find_element_by_xpath('//div[@id="login-message"]')
        assert elem2.get_attribute("innerHTML") == 'Invalid username'

        print ("Verify that unregistered username generates 'User does not exist' message...")
        self.driver.execute_script("$('input#id_auth-username').val('NotRegistered');")
        self.driver.find_element_by_xpath('//button[@id="login"]').click()
        time.sleep(1)
        assert elem2.get_attribute("innerHTML") == 'User does not exist.'

        print ("Verify that good login works ...")
        self.driver.execute_script("$('input#id_auth-username').val('"+self.testuser+"');")
        self.driver.find_element_by_xpath('//button[@id="login"]').click()
        time.sleep(8)  # have to wait for user to touch MFA device
        success_msg = 'Successfully authenticated as ' + self.testuser
        assert elem2.get_attribute("innerHTML") == success_msg
        
    def test02_bad_credential(self):
        """
           test login screen with bad credential
        """
        print ("Logging out of session ...")
        self.url = self.IP+'/account/logout'
        self.open_n_tst_title({'url': self.url, 'title': 'Secure Login'} )
        self.url = self.IP+'/account/login'
        self.open_n_tst_title({'url': self.url, 'title': 'Secure Login'} )
        xpath = '//*[@id="id_auth-username"]'
        self.is_element_present({ 'xpath': xpath})
        elem =  self.driver.find_element_by_xpath(xpath)
        self.driver.execute_script("$('input#id_auth-username').val('"+self.testuser+"');")
        print ("Verify that invalid credential is rejected ...")
        self.driver.find_element_by_xpath('//button[@id="login"]').click()
        time.sleep(8)  # have to wait for user to touch MFA device
        elem2 = self.driver.find_element_by_xpath('//div[@id="login-message"]')
        assert elem2.get_attribute("innerHTML") == 'Error when creating credential'


    def tearDown(self):
        self.driver.quit()
