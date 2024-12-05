import json

class Plugin:
    """
    Plugin class is an object that holds the results of a plugin scan.
    """
    def __init__(self, instanceID: str, name: str, data: str, output: dict):
        self.instanceID = instanceID
        self.name = name
        self.data = data
        self.output = output

    def __str__(self): 
        return f"Plugin: {self.name}, data: {self.data}, output: {self.output}"
    
    def __repr__(self):
        return self.__str__()
    
    def __eq__(self, other):
        return (self.name == other.name and self.data == other.data and self.output == other.output)
        
    def __hash__(self):
        return hash((self.name, self.data, str(self.output)))

    def to_dict(self):
        return {
            'instanceID': self.instanceID,
            'name': self.name,
            'data': self.data,
            'output': self.output,
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            data.get('instanceID', ''),
            data.get('name', ''),
            data.get('data', ''),
            data.get('output', {})
        )

    def to_json(self):
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls.from_dict(data)


class Check:
    """
    Check is an object to test against new plugins.
    Check is a wrapper for the raw data and the plugins results.
    """

    def __init__(self, data:str, tag:str, instanceID:str = ""):
        self.plugins = []
        self.id = instanceID
        self.tag = tag
        self.data = data

    def __str__(self):
        return f"Check: {self.id}, tag: {self.tag}, data: {self.data}, plugins: {self.plugins}"
    
    def __repr__(self):
        return self.__str__()
    
    def to_dict(self):
        return {
            'plugins': self.plugins,
            'id': self.id,
            'tag': self.tag,
            'data': self.data,
        }
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            data.get('data', ''),
            data.get('tag', ''),
            data.get('id', ''),
        )
    
    def to_json(self):
        return json.dumps(self.to_dict())
    
    @classmethod
    def from_json(cls, json_str):
        data = json.loads(json_str)
        return cls.from_dict(data)
    
    def add_plugin(self, pluginName, output):
        """
        Boolean function: returns true if plugin successfully added
        """
        if output == "":
            return False
        current_plugin = Plugin(self.id, pluginName, self.data, output)
        self.plugins.append(current_plugin)
        return True
