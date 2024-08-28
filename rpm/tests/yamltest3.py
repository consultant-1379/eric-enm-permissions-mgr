import re
recompile = re.compile
camelCase=recompile(r'(?<!^)(?=[A-Z])')
name = 'camelCaseName'
name = camelCase.sub('_', name).lower()
print(name)
name = 'camelCaseName2'
name = camelCase.sub('_', name).lower()
print(name)
name = 'camelCaseName3'
name = camelCase.sub('_', name).lower()
print(name)
