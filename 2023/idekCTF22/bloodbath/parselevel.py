import json

known_objs = {
    94: "black box",
    1816: "collision trigger",
    901: "move trigger",
    914: "text",
    8: "spikes"
}

data = open("data/level.json", "r").read()
data = json.loads(data)

objs = data["objects"]

toggles = json.loads(open("data/toggles.json", "r").read())

# for obj in objs:
#     if not 'triggerGroups' in obj.keys():
#         continue
#     if 265 in obj['triggerGroups']:
#         # if obj['id'] in known_objs:
#         #     print(known_objs[obj['id']], end=" ")
#         # print(obj)
#         toggles.append(obj)

# print(len(toggles))

switches = json.loads(open("data/switches.json", "r").read())

# for t in toggles:
#     y = t['y']
#     for obj in objs:
#         if obj['y'] == y or obj['y'] == y + 30:
#             if obj['id'] == 1816 and obj['itemA'] != 2:
#                 switches.append(obj)

# print(len(switches))

triggers = json.loads(open("data/triggers.json", "r").read())

# for obj in objs:
#     if obj['id'] == 901:
#         if 266 <= obj['targetGroupID'] <= 644:
#             triggers.append(obj)

# with open("triggers.json", "w") as f:
#     f.write(json.dumps(triggers, indent=4))

# print(len(triggers))

def getSwitchFromToggleY(y):
    for s in switches:
        if s['y'] == y or s['y'] == y + 30:
            return s

def getSwitchesFromTriggerX(x):
    ret = []
    for s in switches:
        if s['x'] == x:
            ret.append(s)
    return ret

def getToggleFromSwitchY(y):
    for t in toggles:
        if t['y'] == y or t['y'] == y - 30:
            return t

def getTriggerFromSwitchX(x):
    for t in triggers:
        if t['x'] == x:
            return t

def getToggleFromGroupID(id):
    for t in toggles:
        if id in t['triggerGroups']:
            return t

def getTriggerFromGroupID(id):
    for t in triggers:
        if id == t['targetGroupID']:
            return t

def rec(switch, active=True):
    final = []
    # target is a switch, set it to active
    y = switch['y']
    toggle = getToggleFromSwitchY(y)
    trigger = getTriggerFromGroupID(toggle['triggerGroups'][1])
    move = not (active ^ (toggle['y'] == y - 30))

    if trigger == None:
        # no trigger to solve for, must be set as part of input bits
        # if we have to move it, then input bit is set to 1, else 0
        return [toggle['triggerGroups'][1]] if move else []

    on = int(trigger['y'] == 15)
    switches = getSwitchesFromTriggerX(trigger['x'])

    # move the toggle XOR is trigger on
    # if we have to toggle and the trigger is already on, switches must be off
    # if we have to toggle and the trigger is off, switches must come on
    # if we don't toggle and the trigger is on, switches must come on
    # if we don't toggle and the trigger is off, switches must be off
    if move ^ on: 
        final += rec(switches[0], True)
    else:
        for s in switches:
            final += rec(s, False)

    return final


# switch with itemA = 3
target = {'id': 1816, 'x': 49695, 'y': 38145, 'triggerGroups': [1001], 'scale': 0.85, 'itemA': 3}

init = rec(target)
init = [i-9 for i in init] # 9 is the first trigger

bits = [0] * 256
for i in init:
    bits[i] = 1
bits = ''.join([str(b) for b in bits])

from Crypto.Util.number import long_to_bytes
print(long_to_bytes(int(bits, 2)).decode())

# unban_cursed_from_demonlist!1!!1