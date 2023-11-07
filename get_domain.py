import pathlib
import os


def main():
    # open file
    file_path_str = ''
    while file_path_str != '0':
        new_file_data = []
        print("To close the program insert 0")
        file_path_str = input("Insert file name (preferred full path)\n")
        file_path = pathlib.Path(pathlib.PurePath(file_path_str))
        if not file_path.is_file():
            print(f"file {file_path} doesn't exist please check your input")
            continue
        try:
            with open(file_path, 'r') as read_file:
                # read the file with a for loop
                for line in read_file:
                    # Line format user_name@domain.co.xz:p@ssw0rd1234
                    # Get domain by split @
                    tmp_line = line.split("@")
                    # Check if line is valid two parts ["user_name","domain.co.xz:p@ssw0rd1234"]
                    if len(tmp_line) == 2:
                        domain = tmp_line[1]
                        # Remove suffix
                        domain = domain.split(":")[0].split(",")[0]
                        new_file_data.append(domain + ": " + line)
                    else:
                        new_file_data.append("Unknown: "+ line)
        except Exception as e:
            print(f"There was an issue with reading to {file_path.name}: {e}")
        output_file = file_path.with_name("digest_"+file_path.name)
        with open(output_file, 'w') as write_file:
            try:
                write_file.writelines(new_file_data)
            except Exception as e:
                print(f"There was an issue with writing to {'digest_'+file_path.name}: {e}")
            print(f"Saved digested file under: {output_file}")


if __name__ == "__main__":
    main()
