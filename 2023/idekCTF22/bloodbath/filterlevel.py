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

GROUP_OF_INTEREST = 264

print("objs with trigger group", GROUP_OF_INTEREST)
for obj in objs:
    if not 'triggerGroups' in obj.keys():
        continue
    if GROUP_OF_INTEREST in obj['triggerGroups']:
        if obj['id'] in known_objs:
            print(known_objs[obj['id']], end=" ")
        print(obj)

print("\ntriggers that target group", GROUP_OF_INTEREST)
for obj in objs:
    if obj['id'] == 901:
        if GROUP_OF_INTEREST == obj['targetGroupID']:
            print(obj)


