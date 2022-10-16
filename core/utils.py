
from user_agents import parse


class SMSService(object):
    @staticmethod
    def get_sub_classes():
        return [cls for cls in __class__.__subclasses__()]

    def send_message(self, message):
        raise NotImplementedError("concreate class should implement this method")

    @classmethod
    def get_pre_phone_number(cls):
        raise NotImplementedError("concreate class should implement this method")

    @classmethod
    def create_object(cls, phone):
        pre_phone = phone[1:4]
        if pre_phone in cls.get_pre_phone_number():
            return cls()
        return None

    @staticmethod
    def get_object(phone: str):
        lst = []
        for classname in SMSService.get_sub_classes():
            instance = classname.create_object(phone)
            if isinstance(instance, SMSService):
                lst.append(instance)
        return lst


class MTNService(SMSService):
    __PRE_PHONE_NUMBERS = ['935', '936', '937', '938', '939', ]

    @classmethod
    def get_pre_phone_number(cls):
        return cls.__PRE_PHONE_NUMBERS

    def send_message(self, message):
        print("MTN service")
        print(message)


class MCIService(SMSService):
    __PRE_PHONE_NUMBERS = ['911', '912', '913', '914', '915', ]

    @classmethod
    def get_pre_phone_number(cls):
        return cls.__PRE_PHONE_NUMBERS

    def send_message(self, message):
        print("MCI service")
        print(message)


class RIGHTELService(SMSService):
    __PRE_PHONE_NUMBERS = ['943', '944', '945', '946', '947']

    @classmethod
    def get_pre_phone_number(cls):
        return cls.__PRE_PHONE_NUMBERS

    def send_message(self, message):
        print("RIGHTEL service")
        print(message)


class SMSServiceHandler:

    def __init__(self, phone):
        self.phone = phone
        self.sms_service_objects = None

    def create_sms_service_objects(self, phone=None):
        lst = []
        if phone is not None:
            self.phone = phone

        for classname in SMSService.get_sub_classes():
            instance = classname.create_object(self.phone)
            if isinstance(instance, SMSService):
                lst.append(instance)
        self.sms_service_objects = lst
        return lst

    def send_message(self, message, phone=None):
        if self.sms_service_objects is None:
            self.create_sms_service_objects(phone)
        if isinstance(self.sms_service_objects, list):
            for sms_service_obj in self.sms_service_objects:
                if isinstance(sms_service_obj, SMSService):
                    sms_service_obj.send_message(message)


class Client:
    @staticmethod
    def get_user_agent(request):
        return request.META.get('HTTP_USER_AGENT')

    @staticmethod
    def get_authorization_header(request):
        return request.headers.get('Authorization')

    @staticmethod
    def valid_user_agent(request):
        user_agent_str = Client.get_user_agent(request)
        return bool(user_agent_str)
        # if user_agent_str:
        #     userAgent = parse(user_agent_str)
        #     #return userAgent.is_pc or userAgent.is_mobile or userAgent.is_tablet
        # return False


