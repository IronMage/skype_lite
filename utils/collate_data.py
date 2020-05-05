# import sys
import os
import json

class ParseStructuredJSON:
	def __init__(self,base_dir, out_file, mode):
		self.top_dir = base_dir
		self.output_file_name = out_file
		self.mode = mode
		# os.chdir(base_dir)

	def split_numeric(self,my_str):
		rest   = ''.join(c for c in my_str if c.isalpha())
		digits = ''.join(c for c in my_str if c.isdigit())
		return (rest, digits)

	def name_to_values(self,subdir_name):
		my_str_values = subdir_name.split("_")
		my_dict = {}

		for item in my_str_values:
			(value, num_str) = self.split_numeric(item)
			my_dict[value] = int(num_str)

		return my_dict

	def parse_json_file(self,file_name):
		print("checking " + file_name)
		with open(file_name, "r") as fp:
			raw_data = fp.read()
		my_data = json.loads(raw_data)
		return my_data

	def json_to_flat(self,response_data,num_rounds,num_setup):
			# print(response_data)
			if type(response_data) != type({}):
				return []
			ret = []
			client_name = response_data["client"]
			responses   = response_data["responses"]

			for item in responses:
				item["client"] = client_name
				item["Trial"] = str(num_rounds)
				item["Setup"] = str(num_setup)
				ret.append(item)
			return ret

	def run(self):
		self.subdirs = [f for f in os.scandir(self.top_dir) if f.is_dir()]
		print(self.subdirs)

		meta_data = []
		flat_data = []
		new_dir = {}
		num_setup = 0
		for subdir in self.subdirs:
			dict_values = self.name_to_values(subdir.name)
			# os.chdir(subdir.path)
			messages_subdir_files = [f.name for f in os.scandir(subdir.path) if (not f.is_dir() and (f.name).find("Messages.json") != -1)]
			rounds = {}
			num_rounds = 1
			for file in messages_subdir_files:
				message_data  = self.parse_json_file(subdir.path+"/"+file)
				paired_name   = file[:file.find("Messages.json")] + "Responses.json"
				response_data = self.parse_json_file(subdir.path+"/"+paired_name)

				for row in response_data:
					my_flat_data = self.json_to_flat(row, num_rounds, num_setup)
					for flat_item in my_flat_data:
						flat_data.append(flat_item)

				my_meta_cpy = dict(message_data)
				my_meta_cpy.update(dict_values)
				my_meta_cpy["Trial"] = num_rounds
				my_meta_cpy["Setup"] = num_setup
				meta_data.append(my_meta_cpy)

				# print(data)
				rounds["Trial "+str(num_rounds)] = {"messages" : message_data, "responses" : response_data}
				num_rounds = num_rounds + 1
			dir_dict = {"parameters": dict_values, "Trials": rounds}
			new_dir["Setup "+str(num_setup)] = dir_dict
			num_setup = num_setup + 1
		# print(new_dir)
		out_data = json.dumps(new_dir)
		out_meta = json.dumps(meta_data)
		out_flat = json.dumps(flat_data)

		with open(self.output_file_name, "w") as fp:
			if self.mode == "all":
				fp.write(out_data)
			elif self.mode == "meta":
				fp.write(out_meta)
			elif self.mode == "flat":
				fp.write(out_flat)


if __name__ == '__main__':
	p = ParseStructuredJSON("../databases/", "../databases/collated_flat.json", "flat")
	p.run()