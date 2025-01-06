import unittest
from IServer import *
from IPasswordEncoder import *
from AccountManagerResponse import *
from ServerResponse import *
from AccountManager import *
from mockito import *

class TestAccountManager(unittest.TestCase):
    def setUp(self):
        self.Server = mock(IServer)
        self.PasswordEncoder = mock(IPasswordEncoder)
        self.AccountManager = AccountManager(self.Server, self.PasswordEncoder)
        
    def testCallLogin_SUCCEED(self):
        print("testCallLogin_SUCCEED")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        
    def testCallLogin_ALREADY_LOGGED(self):
        print("testCallLogin_ALREADY_LOGGED")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.ALREADY_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogin_ALREADY_LOGGED2(self):
        print("testCallLogin_ALREADY_LOGGED2")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.ALREADY_LOGGED, None))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.ALREADY_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogin_NO_USER_INCORRECT_PASSWORD_RESPONSE(self):
        print("testCallLogin_NO_USER_INCORRECT_PASSWORD_RESPONSE")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.NO_USER_INCORRECT_PASSWORD, None))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.NO_USER_INCORRECT_PASSWORD, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogin_ENCODING_ERROR(self):
        print("testCallLogin_ENCODING_ERROR")
        when(self.PasswordEncoder).makeSecure("b").thenRaise(NullPointerException(Exception))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.ENCODING_ERROR, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogin_UNDEFINED_ERROR(self):
        print("testCallLogin_UNDEFINED_ERROR")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        serResp = ServerResponse(ServerResponse.UNDEFINED_ERROR, None)
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(serResp)
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.UNDEFINED_ERROR, resp.code)
        self.assertEqual(serResp, resp.response)
    
    def testCallLogout_SUCCESS(self):
        print("testCallLogout_SUCCESS")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        when(self.Server).logout(0).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogout("a", 0)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogout_NOT_LOGGED_RESPONSE(self):
        print("testCallLogout_NOT_LOGGED_RESPONSE")
        resp = self.AccountManager.callLogout("a", 0)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogout_NOT_LOGGED_RESPONSE2(self):
        print("testCallLogout_NOT_LOGGED_RESPONSE2")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        when(self.Server).logout(0).thenReturn(ServerResponse(ServerResponse.NOT_LOGGED, None))
        resp = self.AccountManager.callLogout("a", 0)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogout_INCORRECT_SESSION(self):
        print("testCallLogout_INCORRECT_SESSION")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        when(self.Server).logout(1).thenReturn(ServerResponse(ServerResponse.UNDEFINED_ERROR, None))
        resp = self.AccountManager.callLogout("a", 1)
        self.assertEqual(AccountManagerResponse.INCORRECT_SESSION, resp.code)
        self.assertEqual(None, resp.response)
    
    def testCallLogout_UNDEFINED_ERROR(self):
        print("testCallLogout_UNDEFINED_ERROR")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        serResp = ServerResponse(ServerResponse.UNDEFINED_ERROR, None)
        when(self.Server).logout(0).thenReturn(serResp)
        resp = self.AccountManager.callLogout("a", 0)
        self.assertEqual(AccountManagerResponse.UNDEFINED_ERROR, resp.code)
        self.assertEqual(serResp, resp.response)
        
    def testDeposit_SUCCESS(self):
        print("testDeposit_SUCCESS")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 10.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
    
    def testDeposit_NOT_LOGGED(self):
        print("testDeposit_NOT_LOGGED")
        money = 10.0
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testDeposit_NOT_LOGGED2(self):
        print("testDeposit_NOT_LOGGED2")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 10.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.NOT_LOGGED, None))
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testDeposit_INCORRECT_SESSION(self):
        print("testDeposit_INCORRECT_SESSION")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 10.0
        resp = self.AccountManager.deposit("a", 1, money)
        self.assertEqual(AccountManagerResponse. INCORRECT_SESSION, resp.code)
        self.assertEqual(None, resp.response)
    
    def testDeposit_UNDEFINED_ERROR(self):
        print("testDeposit_UNDEFINED_ERROR")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 10.0
        serResp = ServerResponse(ServerResponse.UNDEFINED_ERROR, None)
        when(self.Server).deposit(0, money).thenReturn(serResp)
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.UNDEFINED_ERROR, resp.code)
        self.assertEqual(serResp, resp.response)
    
    def testWithdraw_SUCCESS(self):
        print("testWithdraw_SUCCESS")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 10.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
        moneyW = 5.0
        when(self.Server).withdraw(0, moneyW).thenReturn(ServerResponse(ServerResponse.SUCCESS, money - moneyW))
        resp = self.AccountManager.withdraw("a", 0, moneyW)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money - moneyW, resp.response)
    
    def testWithdraw_NOT_LOGGED(self):
        print("testWithdraw_NOT_LOGGED")
        moneyW = 5.0
        resp = self.AccountManager.withdraw("a", 0, moneyW)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testWithdraw_NOT_LOGGED2(self):
        print("testWithdraw_NOT_LOGGED2")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        moneyW = 5.0
        when(self.Server).withdraw(0, moneyW).thenReturn(ServerResponse(ServerResponse.NOT_LOGGED, None))
        resp = self.AccountManager.withdraw("a", 0, moneyW)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
        
    def testWithdraw_INCORRECT_SESSION(self):
        print("testWithdraw_INCORRECT_SESSION")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        moneyW = 5.0
        when(self.Server).withdraw(1, moneyW).thenReturn(ServerResponse(ServerResponse.UNDEFINED_ERROR, None))
        resp = self.AccountManager.withdraw("a", 1, moneyW)
        self.assertEqual(AccountManagerResponse.INCORRECT_SESSION, resp.code)
        self.assertEqual(None, resp.response)
    
    def testWithdraw_NO_MONEY(self):
        print("testWithdraw_NO_MONEY")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 3.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
        moneyW = 7.0
        when(self.Server).withdraw(0, moneyW).thenReturn(ServerResponse(ServerResponse.NO_MONEY, money))
        resp = self.AccountManager.withdraw("a", 0, moneyW)
        self.assertEqual(AccountManagerResponse.NO_MONEY, resp.code)
        self.assertEqual(money, resp.response)
    
    def testWithdraw_UNDEFINED_ERROR(self):
        print("testWithdraw_UNDEFINED_ERROR")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 3.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
        moneyW = 3.0
        serResp = ServerResponse(ServerResponse.UNDEFINED_ERROR, None)
        when(self.Server).withdraw(0, moneyW).thenReturn(serResp)
        resp = self.AccountManager.withdraw("a", 0, moneyW)
        self.assertEqual(AccountManagerResponse.UNDEFINED_ERROR, resp.code)
        self.assertEqual(serResp, resp.response)
    
    def testGetBalance_SUCCESS(self):
        print("testGetBalance_SUCCESS")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 10.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.deposit("a", 0, money)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
        when(self.Server).getBalance(0).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.getBalance("a", 0)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
    
    def testGetBalance_NOT_LOGGED(self):
        print("testGetBalance_NOT_LOGGED")
        resp = self.AccountManager.getBalance("a", 0)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testGetBalance_NOT_LOGGED2(self):
        print("testGetBalance_NOT_LOGGED2")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        when(self.Server).getBalance(0).thenReturn(ServerResponse(ServerResponse.NOT_LOGGED, None))
        resp = self.AccountManager.getBalance("a", 0)
        self.assertEqual(AccountManagerResponse.NOT_LOGGED, resp.code)
        self.assertEqual(None, resp.response)
    
    def testGetBalance_INCORRECT_SESSION(self):
        print("testGetBalance_INCORRECT_SESSION")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        when(self.Server).getBalance(1).thenReturn(ServerResponse(ServerResponse.UNDEFINED_ERROR, None))
        resp = self.AccountManager.getBalance("a", 1)
        self.assertEqual(AccountManagerResponse.INCORRECT_SESSION, resp.code)
        self.assertEqual(None, resp.response)
    
    def testGetBalance_UNDEFINED_ERROR(self):
        print("testGetBalance_UNDEFINED_ERROR")
        when(self.PasswordEncoder).makeSecure("b").thenReturn("12345")
        when(self.Server).login("a", self.PasswordEncoder.makeSecure("b")).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("a", "b")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        serResp = ServerResponse(ServerResponse.UNDEFINED_ERROR, None)
        when(self.Server).getBalance(0).thenReturn(serResp)
        resp = self.AccountManager.getBalance("a", 0)
        self.assertEqual(AccountManagerResponse.UNDEFINED_ERROR, resp.code)
        self.assertEqual(serResp, resp.response)
    
    def testScript1(self):
        print("testScript1")
        when(self.PasswordEncoder).makeSecure("password").thenReturn("12345")
        when(self.PasswordEncoder).makeSecure("password1").thenReturn("123456")
        when(self.Server).login("user1", any).thenReturn(ServerResponse(ServerResponse.NO_USER_INCORRECT_PASSWORD, None))
        when(self.Server).login("user", "123456").thenReturn(ServerResponse(ServerResponse.NO_USER_INCORRECT_PASSWORD, None))
        when(self.Server).login("user", "12345").thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("user1", "password")
        self.assertEqual(AccountManagerResponse.NO_USER_INCORRECT_PASSWORD, resp.code)
        self.assertEqual(None, resp.response)
        resp = self.AccountManager.callLogin("user", "password1")
        self.assertEqual(AccountManagerResponse.NO_USER_INCORRECT_PASSWORD, resp.code)
        self.assertEqual(None, resp.response)
        resp = self.AccountManager.callLogin("user", "password")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 0.0
        when(self.Server).getBalance(0).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.getBalance("user", 0)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
        money = 100.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.deposit("user", 0, money)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
    
    def testScript2(self):
        when(self.PasswordEncoder).makeSecure("password").thenReturn("12345")
        when(self.Server).login("user", "12345").thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogin("user", "password")
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(0, resp.response)
        money = 0.0
        moneyW = 50.0
        when(self.Server).withdraw(0, moneyW).thenReturn(ServerResponse(ServerResponse.NO_MONEY, money))
        resp = self.AccountManager.withdraw("user", 0, moneyW)
        self.assertEqual(AccountManagerResponse.NO_MONEY, resp.code)
        self.assertEqual(money, resp.response)
        money += 100.0
        when(self.Server).deposit(0, money).thenReturn(ServerResponse(ServerResponse.SUCCESS, money))
        resp = self.AccountManager.deposit("user", 0, money)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money, resp.response)
        resp = self.AccountManager.withdraw("user", 1, moneyW)
        self.assertEqual(AccountManagerResponse.INCORRECT_SESSION, resp.code)
        self.assertEqual(None, resp.response)
        when(self.Server).withdraw(0, moneyW).thenReturn(ServerResponse(ServerResponse.SUCCESS, money - moneyW))
        resp = self.AccountManager.withdraw("user", 0, moneyW)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(money - moneyW, resp.response)
        when(self.Server).logout(0).thenReturn(ServerResponse(ServerResponse.SUCCESS, 0))
        resp = self.AccountManager.callLogout("user", 0)
        self.assertEqual(AccountManagerResponse.SUCCEED, resp.code)
        self.assertEqual(None, resp.response)
        
        
        
if __name__ == "__main__":
    unittest.main()
