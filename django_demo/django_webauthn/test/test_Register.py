#!/usr/bin/python 

import re
import sys
import time
from SeleniumUtils import SeleniumHelper

class testRegister(SeleniumHelper):

    def setUp(self):
        self.cfg()
        self.url=self.IP+'/account/register'

    def test01_register(self):
        """
           verify username and diaplay name input in register screen
        """
        self.open_n_tst_title({'url': self.url, 'title': 'Registration'} )

        print ("Verify that empty username generates 'Invalid username' message...")
        xpath = '//*[@id="id_auth-username"]'
        self.is_element_present({ 'xpath': xpath})
        elem =  self.driver.find_element_by_xpath(xpath)
        self.driver.execute_script("$('input#id_auth-username').val('');")
        self.driver.find_element_by_xpath('//button[@id="register"]').click()
        elem2 = self.driver.find_element_by_xpath('//div[@id="login-message"]')
        assert elem2.get_attribute("innerHTML") == 'Invalid username'

        print ("Verify that empty  display name generates 'Invalid display name' message...")
        self.driver.execute_script("$('input#id_auth-username').val('"+self.testuser+"');")
        self.driver.execute_script("$('input#id_auth-dispname').val('');")
        self.driver.find_element_by_xpath('//button[@id="register"]').click()
        time.sleep(1)
        elem2 = self.driver.find_element_by_xpath('//div[@id="login-message"]')
        assert elem2.get_attribute("innerHTML") == 'Invalid display name'

        print ("Verify that proper registration works...")
        self.driver.execute_script("$('input#id_auth-username').val('"+self.testuser+"');")
        self.driver.execute_script("$('input#id_auth-dispname').val('"+self.testuser+"');")
        self.driver.find_element_by_xpath('//button[@id="register"]').click()
        # import ipdb; ipdb.def_colors='NoColor'; ipdb.set_trace() # BREAKPOINT
        time.sleep(8)  # have to wait for user to touch MFA device
        status_text = self.driver.execute_script("return $('div#login-message').text()")
        assert status_text == 'User successfully registered'

        self.open_n_tst_title({'url': self.url, 'title': 'Registration'} )
        print ("Verify that duplicate username in registration is detected...")
        self.driver.execute_script("$('input#id_auth-username').val('"+self.testuser+"');")
        self.driver.execute_script("$('input#id_auth-dispname').val('"+self.testuser+"');")
        self.driver.find_element_by_xpath('//button[@id="register"]').click()
        time.sleep(1)
        elem2 = self.driver.find_element_by_xpath('//div[@id="login-message"]')
        assert elem2.get_attribute("innerHTML") == 'User already exists.'

    def tearDown(self):
        self.driver.quit()
