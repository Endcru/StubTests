from IServer import *
from IPasswordEncoder import *
from AccountManagerResponse import *
from ServerResponse import *

class AccountManager:
    server: IServer
    activeAccounts = dict[str, int]()
    passEncoder: IPasswordEncoder

    def __init__(self, s: IServer, encoder: IPasswordEncoder):
        self.server = s
        self.passEncoder = encoder
        self.activeAccounts = dict[str, int]()

    def callLogin(self, login: str, password: str) -> AccountManagerResponse:
        sess: int = self.activeAccounts.get(login)
        if sess is not None:
            return ACCOUNT_MANAGER_RESPONSE
        try:
            passcod = self.passEncoder.makeSecure(password)
        except NullPointerException:
            return ENCODING_ERROR_RESPONSE
        ret: ServerResponse = self.server.login(login, passcod)
        match ret.code:
            case ServerResponse.ALREADY_LOGGED:
                return ACCOUNT_MANAGER_RESPONSE
            case ServerResponse.NO_USER_INCORRECT_PASSWORD:
                return NO_USER_INCORRECT_PASSWORD_RESPONSE
            case ServerResponse.SUCCESS:
                resp = ret.response
                if isinstance(resp, int):
                    self.activeAccounts[login] = resp
                    return AccountManagerResponse(AccountManagerResponse.SUCCEED, resp)
        return AccountManagerResponse(AccountManagerResponse.UNDEFINED_ERROR, ret)

    def callLogout(self, user: str, session: int) -> AccountManagerResponse:
        rem: int = self.activeAccounts.get(user, None)
        if rem is None:
            return NOT_LOGGED_RESPONSE
        if rem != session:
            return INCORRECT_SESSION_RESPONSE
        rem: int = self.activeAccounts.pop(user, None)
        resp: ServerResponse = self.server.logout(session)
        match resp.code:
            case ServerResponse.NOT_LOGGED:
                return NOT_LOGGED_RESPONSE
            case ServerResponse.SUCCESS:
                return SUCCEED_RESPONSE
        return AccountManagerResponse(AccountManagerResponse.UNDEFINED_ERROR, resp)

    def withdraw(self, user: str, session: int, amount: float):
        stored: int = self.activeAccounts.get(user, None)
        if stored is None:
            return NOT_LOGGED_RESPONSE
        if stored != session:
            return INCORRECT_SESSION_RESPONSE
        resp: ServerResponse = self.server.withdraw(session, amount)
        match resp.code:
            case ServerResponse.NOT_LOGGED:
                return NOT_LOGGED_RESPONSE
            case ServerResponse.NO_MONEY:
                r = resp.response
                if r is not None and (isinstance(r, float)):
                    return AccountManagerResponse(AccountManagerResponse.NO_MONEY, r)
            case ServerResponse.SUCCESS:
                r = resp.response
                if r is not None and (isinstance(r, float)):
                    return AccountManagerResponse(AccountManagerResponse.SUCCEED, r)
        return AccountManagerResponse(AccountManagerResponse.UNDEFINED_ERROR, resp)

    def deposit(self, user: str, session: int, amount: float) -> AccountManagerResponse:
        stored: int = self.activeAccounts.get(user, None)
        if stored is None:
            return NOT_LOGGED_RESPONSE
        if stored != session:
            return INCORRECT_SESSION_RESPONSE
        resp: ServerResponse = self.server.deposit(session, amount)
        match resp.code:
            case ServerResponse.NOT_LOGGED:
                return NOT_LOGGED_RESPONSE
            case ServerResponse.SUCCESS:
                r = resp.response
                if r is not None and (isinstance(r, float)):
                    return AccountManagerResponse(AccountManagerResponse.SUCCEED, r)
        return AccountManagerResponse(AccountManagerResponse.UNDEFINED_ERROR, resp)

    def getBalance(self, user: str, session: int) -> AccountManagerResponse:
        stored: int = self.activeAccounts.get(user, None)
        if stored is None:
            return NOT_LOGGED_RESPONSE
        if stored != session:
            return INCORRECT_SESSION_RESPONSE
        resp: ServerResponse = self.server.getBalance(session)
        match resp.code:
            case ServerResponse.NOT_LOGGED:
                return NOT_LOGGED_RESPONSE
            case ServerResponse.SUCCESS:
                r = resp.response
                if r is not None and (isinstance(r, float)):
                    return AccountManagerResponse(AccountManagerResponse.SUCCEED, r)
        return AccountManagerResponse(AccountManagerResponse.UNDEFINED_ERROR, resp)
