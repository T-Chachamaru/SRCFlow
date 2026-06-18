import os
 
def make_boom(file_path, file_num, string_len):
    if not os.path.exists(file_path):
        os.mkdir(file_path)
    os.chdir(file_path)
    for i in range(file_num):
        with open('boom%d.txt' % i, 'w',encoding='utf-8') as f:
            f.write('Boom' * string_len)
 
make_boom('zip_boom', 1000, 1000 * 1000)