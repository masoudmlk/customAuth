class SMSService:
    MTN_PRE_NUMBER = ['935', '936', '937', '938', '939', ]
    MCI_PRE_NUMBER = ['911', '912', '913', '914', '915', ]
    RIGHTEL_PRE_NUMBER = ['943', '944', '945', '946', '947', ]

    @staticmethod
    def get_object(phone: str):
        prefixPhone = None
        if len(phone) > 4:
            prefixPhone = phone[1:4]
        if prefixPhone is not None:
            if prefixPhone in SMSService.MTN_PRE_NUMBER:
                return MTNSerivice()
            elif prefixPhone in SMSService.MCI_PRE_NUMBER:
                return MCIService()
            elif prefixPhone in SMSService.RIGHTEL_PRE_NUMBER:
                return RIGHTELService()
            else:
                raise ValueError("invalid value for service")
        raise ValueError("invalid phone number")

    def send_message(self, message):
        raise NotImplementedError("concreate class should implement this method")


class MTNSerivice(SMSService):
    def send_message(self, message):
        print("MTN service")
        print(message)


class MCIService(SMSService):
    def send_message(self, message):
        print("MCI service")
        print(message)


class RIGHTELService(SMSService):
    def send_message(self, message):
        print("RIGHTEL service")
        print(message)


class Client:
    @staticmethod
    def get_user_agent(request):
        return request.META.get('HTTP_USER_AGENT')
