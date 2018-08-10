# import hashlib
# import logging
# import time
# from base64 import b64decode, b64encode
# from collections import OrderedDict
# from threading import Event
#
# import requests
# import stringcase
# from sleekxmpp import ClientXMPP, Callback, MatchXPath
# from sleekxmpp.xmlstream import ET
# from sleekxmpp.exceptions import XMPPError
#
# _LOGGER = logging.getLogger(__name__)

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
#puts COMPONENT_FROM_ECOVACS['dust_case_heap']
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
      login_info = call_main_api('user/login', '')
    #    ,('account'
    #    , ''#encrypt(account_id))
    #  , ('password', ''#encrypt(password_hash)))
    #  uid = login_info['uid']
      #login_access_token = login_info['accessToken']
      #auth_code = call_main_api('user/getAuthCode',
      #  ('uid', uid),
      #  ('accessToken', login_access_token))['authCode']
      #user_access_token = __call_login_by_it_token()['token']
      puts "EcoVacsAPI connection complete"
    end

    def sign(params)
  #    result = params.copy()
  #    result['authTimespan'] = int(time.time() * 1000)
  #    result['authTimeZone'] = 'GMT-8'

  #    sign_on = meta.copy()
  #    sign_on.update(result)
  #    sign_on_text = EcoVacsAPI.CLIENT_KEY + ''.join(
  #      [k + '=' + str(sign_on[k]) for k in sorted(sign_on.keys())]) + EcoVacsAPI.SECRET

  #    result['authAppkey'] = EcoVacsAPI.CLIENT_KEY
  #    result['authSign'] = md5(sign_on_text)
  #    return result
    end

    def call_main_api(function, *args)
      puts "calling main api #{function} with #{args}"#.format(function, args))
      #params = OrderedDict(args)
      #params['requestId'] = md5(time.time())
      #url = (EcoVacsAPI.MAIN_URL_FORMAT + "/" + function).format(**meta)
      #api_response = requests.get(url, __sign(params))
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
      #response = requests.post(EcoVacsAPI.USER_URL_FORMAT.format(continent=continent), json=params)
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
      return call_user_api('loginByItToken',
        {'country' => meta['country'].upper(),
          'resource' => resource,
          'realm' => EcoVacsAPI.REALM,
          'userId' => uid,
          'token' => auth_code}
        )
    end

    def devices()
      devices = call_user_api('GetDeviceList', {
        'userid' => uid,
        'auth' => {
          'with' => 'users',
          'userid' => uid,
          'realm' => EcoVacsAPI.REALM,
          'token' => user_access_token,
          'resource' => resource
        }
      })['devices']

      return devices
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

# class EventEmitter(object):
#     """A very simple event emitting system."""
#     def initialize()
#         _subscribers = []
#
#     def subscribe(callback):
#         listener = EventListener(callback)
#         _subscribers.append(listener)
#         return listener
#
#     def unsubscribe(listener):
#         _subscribers.remove(listener)
#
#     def notify(event):
#         for subscriber in _subscribers:
#             subscriber.callback(event)
#
#
# class EventListener(object):
#     """Object that allows event consumers to easily unsubscribe from events."""
#     def initialize(emitter, callback):
#         _emitter = emitter
#         callback = callback
#
#     def unsubscribe()
#         _emitter.unsubscribe(self)
#
#
# class VacBot():
#     def initialize(user, domain, resource, secret, vacuum, continent, server_address=None, monitor=False):
#
#         vacuum = vacuum
#
#         # If True, the VacBot object will handle keeping track of all statuses,
#         # including the initial request for statuses, and new requests after the
#         # VacBot returns from being offline. It will also cause it to regularly
#         # request component lifespans
#         _monitor = monitor
#
#         _failed_pings = 0
#
#         # These three are representations of the vacuum state as reported by the API
#         clean_status = None
#         charge_status = None
#         battery_status = None
#
#         # This is an aggregate state managed by the sucks library, combining the clean and charge events to a single state
#         vacuum_status = None
#         fan_speed = None
#
#         # Populated by component Lifespan reports
#         components = {}
#
#         statusEvents = EventEmitter()
#         batteryEvents = EventEmitter()
#         lifespanEvents = EventEmitter()
#         errorEvents = EventEmitter()
#
#         xmpp = EcoVacsXMPP(user, domain, resource, secret, continent, server_address)
#         xmpp.subscribe_to_ctls(_handle_ctl)
#
#     def connect_and_wait_until_ready()
#         xmpp.connect_and_wait_until_ready()
#
#         xmpp.schedule('Ping', 30, lambda => send_ping(), repeat=True)
#
#         if _monitor:
#             # Do a first ping, which will also fetch initial statuses if the ping succeeds
#             send_ping()
#             xmpp.schedule('Components', 3600, lambda => refresh_components(), repeat=True)
#
#     def _handle_ctl(ctl):
#         method = '_handle_' + ctl['event']
#         if hasattr(method):
#             getattr(method)(ctl)
#
#     def _handle_error(event):
#         error = event['error']
#         errorEvents.notify(error)
#         _LOGGER.debug("*** error = " + error)
#
#     def _handle_life_span(event):
#         type = event['type']
#         try:
#             type = COMPONENT_FROM_ECOVACS[type]
#         except KeyError:
#             _LOGGER.warning("Unknown component type => '" + type + "'")
#
#         total = float(event['total'])
#         val = float(event['val'])
#         lifespan = val / total
#         components[type] = lifespan
#
#         lifespan_event = {'type' => type, 'lifespan' => lifespan}
#         lifespanEvents.notify(lifespan_event)
#         _LOGGER.debug("*** life_span " + type + " = " + str(lifespan))
#
#     def _handle_clean_report(event):
#         type = event['type']
#         try:
#             type = CLEAN_MODE_FROM_ECOVACS[type]
#         except KeyError:
#             _LOGGER.warning("Unknown cleaning status '" + type + "'")
#         clean_status = type
#         vacuum_status = type
#         fan = event.get('speed', None)
#         if fan is not None:
#             try:
#                 fan = FAN_SPEED_FROM_ECOVACS[fan]
#             except KeyError:
#                 _LOGGER.warning("Unknown fan speed => '" + fan + "'")
#         fan_speed = fan
#         statusEvents.notify(vacuum_status)
#         if fan_speed:
#             _LOGGER.debug("*** clean_status = " + clean_status + " fan_speed = " + fan_speed)
#         else:
#             _LOGGER.debug("*** clean_status = " + clean_status + " fan_speed = None")
#
#     def _handle_battery_info(iq):
#         try:
#             battery_status = float(iq['power']) / 100
#         except ValueError:
#             _LOGGER.warning("couldn't parse battery status " + ET.tostring(iq))
#         else:
#             batteryEvents.notify(battery_status)
#             _LOGGER.debug("*** battery_status = {:.0%}".format(battery_status))
#
#     def _handle_charge_state(event):
#         status = event['type']
#         try:
#             status = CHARGE_MODE_FROM_ECOVACS[status]
#         except KeyError:
#             _LOGGER.warning("Unknown charging status '" + status + "'")
#
#         charge_status = status
#         if status != 'idle' or vacuum_status == 'charging':
#             # We have to ignore the idle messages, because all it means is that it's not
#             # currently charging, in which case the clean_status is a better indicator
#             # of what the vacuum is currently up to.
#             vacuum_status = status
#             statusEvents.notify(vacuum_status)
#         _LOGGER.debug("*** charge_status = " + charge_status)
#
#     def _vacuum_address()
#         return vacuum['did'] + '@' + vacuum['class'] + '.ecorobot.net/atom'
#
#     @property
#     def is_charging(self) -> bool:
#         return vacuum_status in CHARGING_STATES
#
#     @property
#     def is_cleaning(self) -> bool:
#         return vacuum_status in CLEANING_STATES
#
#     def send_ping()
#         try:
#             xmpp.send_ping(_vacuum_address())
#         except XMPPError as err:
#             _LOGGER.warning("Ping did not reach VacBot. Will retry.")
#             _LOGGER.debug("*** Error type: " + err.etype)
#             _LOGGER.debug("*** Error condition: " + err.condition)
#             _failed_pings += 1
#             if _failed_pings >= 4:
#                 vacuum_status = 'offline'
#                 statusEvents.notify(vacuum_status)
#         else:
#             _failed_pings = 0
#             if _monitor:
#                 # If we don't yet have a vacuum status, request initial statuses again now that the ping succeeded
#                 if vacuum_status == 'offline' or vacuum_status is None:
#                     request_all_statuses()
#             else:
#                 # If we're not auto-monitoring the status, then just reset the status to None, which indicates unknown
#                 if vacuum_status == 'offline':
#                     vacuum_status = None
#                     statusEvents.notify(vacuum_status)
#
#     def refresh_components()
#         try:
#             run(GetLifeSpan('main_brush'))
#             run(GetLifeSpan('side_brush'))
#             run(GetLifeSpan('filter'))
#         except XMPPError as err:
#             _LOGGER.warning("Component refresh requests failed to reach VacBot. Will try again later.")
#             _LOGGER.debug("*** Error type: " + err.etype)
#             _LOGGER.debug("*** Error condition: " + err.condition)
#
#     def request_all_statuses()
#         try:
#             run(GetCleanState())
#             run(GetChargeState())
#             run(GetBatteryState())
#         except XMPPError as err:
#             _LOGGER.warning("Initial status requests failed to reach VacBot. Will try again on next ping.")
#             _LOGGER.debug("*** Error type: " + err.etype)
#             _LOGGER.debug("*** Error condition: " + err.condition)
#         else:
#             refresh_components()
#
#     def send_command(xml):
#         xmpp.send_command(xml, _vacuum_address())
#
#     def run(action):
#         send_command(action.to_xml())
#
#     def disconnect(wait=False):
#         xmpp.disconnect(wait=wait)
#
#
class EcoVacsXMPP#(ClientXMPP)
  def initialize(user, domain, resource, secret, continent, server_address=Nil)
    ClientXMPP.initialize(user + '@' + domain, '0/' + resource + '/' + secret)

    user = user
    domain = domain
    resource = resource
    continent = continent
    credentials['authzid'] = user

    if server_address is Nil
#      server_address = ('msg-{}.ecouser.net'.format(continent), '5223')
    else
      server_address = server_address
    end

#    add_event_handler("session_start", session_start)
#    ctl_subscribers = []
#    ready_flag = Event()
  end

  def wait_until_ready()
    ready_flag.wait()
  end

#     def session_start(event):
#         _LOGGER.debug("----------------- starting session ----------------")
#         _LOGGER.debug("event = {}".format(event))
#         register_handler(Callback("general",
#                                        MatchXPath('{jabber:client}iq/{com:ctl}query/{com:ctl}'),
#                                        _handle_ctl))
#         ready_flag.set()
#
#     def subscribe_to_ctls(function):
#         ctl_subscribers.append(function)
#
#     def _handle_ctl(message):
#         the_good_part = message.get_payload()[0][0]
#         as_dict = _ctl_to_dict(the_good_part)
#         if as_dict is not None:
#             for s in ctl_subscribers:
#                 s(as_dict)
#
#     def _ctl_to_dict(xml):
#         result = xml.attrib.copy()
#         if 'td' not in result:
#             # This happens for commands with no response data, such as PlaySound
#             return
#
#         result['event'] = result.pop('td')
#         if xml:
#             result.update(xml[0].attrib)
#
#         for key in result:
#             result[key] = stringcase.snakecase(result[key])
#         return result
#
#     def register_callback(kind, function):
#         register_handler(Callback(kind,
#                                        MatchXPath('{jabber:client}iq/{com:ctl}query/{com:ctl}ctl[@td="' + kind + '"]'),
#                                        function))
#
#     def send_command(xml, recipient):
#         c = _wrap_command(xml, recipient)
#         _LOGGER.debug('Sending command {0}'.format(c))
#         c.send()
#
#     def _wrap_command(ctl, recipient):
#         q = make_iq_query(xmlns=u'com:ctl', ito=recipient, ifrom=_my_address())
#         q['type'] = 'set'
#         for child in q.xml:
#             if child.tag.endswith('query'):
#                 child.append(ctl)
#                 return q
#
#     def _my_address()
#         return user + '@' + domain + '/' + resource
#
#     def send_ping(to):
#         q = make_iq_get(ito=to, ifrom=_my_address())
#         q.xml.append(ET.Element('ping', {'xmlns': 'urn:xmpp:ping'}))
#         _LOGGER.debug("*** sending ping ***")
#         q.send()
#
#     def connect_and_wait_until_ready()
#         connect(server_address)
#         process()
#         wait_until_ready()
end

class VacBotCommand
  ACTION = {
    'forward' => 'forward',
    'left' => 'SpinLeft',
    'right' => 'SpinRight',
    'turn_around' => 'TurnAround',
    'stop' => 'stop'
  }

  def initialize(name, args = Nil)
    if args is Nil
      args = {}
    end
    name = name
    args = args
  end

  def to_xml()
#    ctl = ET.Element('ctl', {'td': name})
#         for key, value in args.items():
#             if type(value) is dict:
#                 inner = ET.Element(key, value)
#                 ctl.append(inner)
#             else:
#                 ctl.set(key, value)
    return ctl
  end

  def __str__(*args, **kwargs)
#    return command_name() + " command"
  end

  def command_name()
#    return __class__.__name__.lower()
  end
end

class Clean#(VacBotCommand)
  def initialize(mode='auto', speed='normal', terminal=False)
#    super().initialize('Clean', {'clean': {'type': CLEAN_MODE_TO_ECOVACS[mode], 'speed': FAN_SPEED_TO_ECOVACS[speed]}})
  end
end

class Edge#(Clean)
  def initialize()
#    super().initialize('edge', 'high')
  end
end

class Spot#(Clean)
  def initialize()
#    super().initialize('spot', 'high')
  end
end

class Stop#(Clean)
  def initialize
#    super().initialize('stop', 'normal')
  end
end

class Charge#(VacBotCommand)
  def initialize
#    super().initialize('Charge', {'charge': {'type': CHARGE_MODE_TO_ECOVACS['return']}})
  end
end

class Move#(VacBotCommand)
  def initialize(action)
#    super().initialize('Move', {'move': {'action': ACTION[action]}})
  end
end

class PlaySound#(VacBotCommand)
  def initialize(sid="0")
#    super().initialize('PlaySound', {'sid': sid})
  end
end

class GetCleanState#(VacBotCommand)
  def initialize()
#    super().initialize('GetCleanState')
  end
end

class GetChargeState#(VacBotCommand)
  def initialize()
#    super().initialize('GetChargeState')
  end
end

class GetBatteryState#(VacBotCommand)
  def initialize()
#    super().initialize('GetBatteryInfo')
  end
end

class GetLifeSpan#(VacBotCommand)
  def initialize(component)
#    super().initialize('GetLifeSpan', {'type': COMPONENT_TO_ECOVACS[component]})
  end
end

class SetTime#(VacBotCommand)
  def initialize(timestamp, timezone)
#    super().initialize('SetTime', {'time': {'t': timestamp, 'tz': timezone}})
  end
end

#########################
api = EcoVacsAPI.new("1234567890120", 2, 3, 4, 5)
#puts api.meta
#########################
