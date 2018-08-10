CLEAN_MODE_AUTO = 'auto'
CLEAN_MODE_EDGE = 'edge'
CLEAN_MODE_SPOT = 'spot'
CLEAN_MODE_SINGLE_ROOM = 'single_room'
CLEAN_MODE_STOP = 'stop'

FAN_SPEED_NORMAL = 'normal'
FAN_SPEED_HIGH = 'high'

CHARGE_MODE_RETURN = 'return'
CHARGE_MODE_RETURNING = 'returning'
CHARGE_MODE_CHARGING = 'charging'
CHARGE_MODE_IDLE = 'idle'

COMPONENT_SIDE_BRUSH = 'side_brush'
COMPONENT_MAIN_BRUSH = 'main_brush'
COMPONENT_FILTER = 'filter'

VACUUM_STATUS_OFFLINE = 'offline'

CLEANING_STATES = [CLEAN_MODE_AUTO, CLEAN_MODE_EDGE, CLEAN_MODE_SPOT, CLEAN_MODE_SINGLE_ROOM]
CHARGING_STATES = [CHARGE_MODE_CHARGING]

# These dictionaries convert to and from Sucks's consts (which closely match what the UI and manuals use)
# to and from what the Ecovacs API uses (which are sometimes very oddly named and have random capitalization.)
CLEAN_MODE_TO_ECOVACS = {
    CLEAN_MODE_AUTO => 'auto',
    CLEAN_MODE_EDGE => 'border',
    CLEAN_MODE_SPOT => 'spot',
    CLEAN_MODE_SINGLE_ROOM => 'singleroom',
    CLEAN_MODE_STOP => 'stop'
}

CLEAN_MODE_FROM_ECOVACS = {
    'auto' => CLEAN_MODE_AUTO,
    'border' => CLEAN_MODE_EDGE,
    'spot' => CLEAN_MODE_SPOT,
    'singleroom' => CLEAN_MODE_SINGLE_ROOM,
    'stop' => CLEAN_MODE_STOP,
    'going' => CHARGE_MODE_RETURNING
}

FAN_SPEED_TO_ECOVACS = {
    FAN_SPEED_NORMAL => 'standard',
    FAN_SPEED_HIGH => 'strong'
}

FAN_SPEED_FROM_ECOVACS = {
    'standard' => FAN_SPEED_NORMAL,
    'strong' => FAN_SPEED_HIGH
}

CHARGE_MODE_TO_ECOVACS = {
    CHARGE_MODE_RETURN => 'go',
    CHARGE_MODE_RETURNING => 'Going',
    CHARGE_MODE_CHARGING => 'SlotCharging',
    CHARGE_MODE_IDLE => 'Idle'
}

CHARGE_MODE_FROM_ECOVACS = {
    'going' => CHARGE_MODE_RETURNING,
    'slot_charging' => CHARGE_MODE_CHARGING,
    'idle' => CHARGE_MODE_IDLE
}

COMPONENT_TO_ECOVACS = {
    COMPONENT_MAIN_BRUSH => 'Brush',
    COMPONENT_SIDE_BRUSH => 'SideBrush',
    COMPONENT_FILTER => 'DustCaseHeap'
}

COMPONENT_FROM_ECOVACS = {
    'brush' => COMPONENT_MAIN_BRUSH,
    'side_brush' => COMPONENT_SIDE_BRUSH,
    'dust_case_heap' => COMPONENT_FILTER
}

#########################
puts COMPONENT_FROM_ECOVACS['dust_case_heap']
#########################

class EcoVacsAPI
    CLIENT_KEY = "eJUWrzRv34qFSaYk"
    SECRET = "Cyu5jcR4zyK6QEPn1hdIGXB5QIDAQABMA0GC"
    PUBLIC_KEY = 'MIIB/TCCAWYCCQDJ7TMYJFzqYDANBgkqhkiG9w0BAQUFADBCMQswCQYDVQQGEwJjbjEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMCAXDTE3MDUwOTA1MTkxMFoYDzIxMTcwNDE1MDUxOTEwWjBCMQswCQYDVQQGEwJjbjEVMBMGA1UEBwwMRGVmYXVsdCBDaXR5MRwwGgYDVQQKDBNEZWZhdWx0IENvbXBhbnkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDb8V0OYUGP3Fs63E1gJzJh+7iqeymjFUKJUqSD60nhWReZ+Fg3tZvKKqgNcgl7EGXp1yNifJKUNC/SedFG1IJRh5hBeDMGq0m0RQYDpf9l0umqYURpJ5fmfvH/gjfHe3Eg/NTLm7QEa0a0Il2t3Cyu5jcR4zyK6QEPn1hdIGXB5QIDAQABMA0GCSqGSIb3DQEBBQUAA4GBANhIMT0+IyJa9SU8AEyaWZZmT2KEYrjakuadOvlkn3vFdhpvNpnnXiL+cyWy2oU1Q9MAdCTiOPfXmAQt8zIvP2JC8j6yRTcxJCvBwORDyv/uBtXFxBPEC6MDfzU2gKAaHeeJUWrzRv34qFSaYkYta8canK+PSInylQTjJK9VqmjQ'
    MAIN_URL_FORMAT = 'https://eco-{country}-api.ecovacs.com/v1/private/{country}/{lang}/{deviceId}/{appCode}/{appVersion}/{channel}/{deviceType}'
    USER_URL_FORMAT = 'https://users-{continent}.ecouser.net:8000/user.do'
    REALM = 'ecouser.net'

    def initialize(device_id, account_id, password_hash, country, continent)
      @meta = {
        'country' => country,
        'lang' => 'en',
        'deviceId' => device_id,
        'appCode' => 'i_eco_e',
        'appVersion' => '1.3.5',
        'channel' => 'c_googleplay',
        'deviceType' => '1'
        }
      puts "Setting up EcoVacsAPI"
      resource = device_id[0,8]
      country = country
      continent = continent
      #login_info = call_main_api('user/login',
      #  ('account', self.encrypt(account_id)),
      #  ('password', self.encrypt(password_hash)))
      #uid = login_info['uid']
      #login_access_token = login_info['accessToken']
      #auth_code = call_main_api('user/getAuthCode',
      #  ('uid', self.uid),
      #  ('accessToken', self.login_access_token))['authCode']
      #user_access_token = self.__call_login_by_it_token()['token']
      puts "EcoVacsAPI connection complete"
    end

    def sign(params)
  #    result = params.copy()
  #    result['authTimespan'] = int(time.time() * 1000)
  #    result['authTimeZone'] = 'GMT-8'

  #    sign_on = self.meta.copy()
  #    sign_on.update(result)
  #    sign_on_text = EcoVacsAPI.CLIENT_KEY + ''.join(
  #      [k + '=' + str(sign_on[k]) for k in sorted(sign_on.keys())]) + EcoVacsAPI.SECRET

  #    result['authAppkey'] = EcoVacsAPI.CLIENT_KEY
  #    result['authSign'] = self.md5(sign_on_text)
  #    return result
    end

    def call_main_api(function, *args)
      #puts "calling main api {} with {}".format(function, args))
      #params = OrderedDict(args)
      #params['requestId'] = self.md5(time.time())
      #url = (EcoVacsAPI.MAIN_URL_FORMAT + "/" + function).format(**self.meta)
      #api_response = requests.get(url, self.__sign(params))
      #json = api_response.json()
      #puts "got {}".format(json)
      #if json['code'] == '0000':
      #  return json['data']
      #elsif json['code'] == '1005':
      #  puts "incorrect email or password"
      #  raise ValueError("incorrect email or password")
      #else:
      #  puts "call to {} failed with {}".format(function, json)
      #  raise RuntimeError("failure code {} ({}) for call {} and parameters {}".format(
      #      json['code'], json['msg'], function, args))
      #end
    end

    def call_user_api(function, args)
      puts "calling user api #{function} with #{args}"
      #params = {'todo': function}
      #params.update(args)
      #response = requests.post(EcoVacsAPI.USER_URL_FORMAT.format(continent=self.continent), json=params)
      #json = response.json()
      #puts "got {}".format(json)
      #if json['result'] == 'ok':
      #  return json
      #else:
      #  _LOGGER.error("call to {} failed with {}".format(function, json))
      #  raise RuntimeError(
      #    "failure {} ({}) for call {} and parameters {}".format(json['error'], json['errno'], function, params))
      #  end
    end

    def call_login_by_it_token()
    #  return call_user_api('loginByItToken',
    #    {'country': self.meta['country'].upper(),
    #      'resource': self.resource,
    #      'realm': EcoVacsAPI.REALM,
    #      'userId': self.uid,
    #      'token': self.auth_code}
    #    )
    end

    def devices()
    #  devices = call_user_api('GetDeviceList', {
    #    'userid': uid,
    #    'auth': {
    #      'with': 'users',
    #      'userid': uid,
    #      'realm': EcoVacsAPI.REALM,
    #      'token': user_access_token,
    #      'resource': resource
    #    }
    #  })['devices']

    #  return devices
    end

    #@staticmethod
    def md5(text)
      #return hashlib.md5(bytes(str(text), 'utf8')).hexdigest()
    end

    #@staticmethod
    def encrypt(text)
      #from Crypto.PublicKey import RSA
      #from Crypto.Cipher import PKCS1_v1_5
      #key = RSA.import_key(b64decode(EcoVacsAPI.PUBLIC_KEY))
      #cipher = PKCS1_v1_5.new(key)
      #result = cipher.encrypt(bytes(text, 'utf8'))
      #return str(b64encode(result), 'utf8')
    end
end

#########################
api = EcoVacsAPI.new("1234567890120", 2, 3, 4, 5)
#puts api.meta
#########################
