import json
from .parser import Parser
from .detector import Detection

class Pipeline():
    def __init__(self, current_file, file_name):
        parser = Parser()
        self.data_list = parser.parsing(current_file)
        self.file_to_write = file_name

    def store_to_json(self):
        with open(self.file_to_write, "w") as f:
            for data in self.data_list:
                detector = Detection(data)
                detected = detector.process()
                json.dump(detected, f)
                f.write("\n")
            print("The Json file is written succefully!")




