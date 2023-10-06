import numpy as np # solving numerical 
import pandas as pd # used for data science and analytics , ML. built on top of numpy
import matplotlib.pyplot as plt # used for graphs and plots
import seaborn as sns # data visualization 
import time
import csv

#--- Send Mail

# Imports

import smtplib

def Send_EMail_Method(Intrusion_Type):
    # SET EMAIL LOGIN REQUIREMENTS
    gmail_user = 'msubhash535@gmail.com'
    gmail_app_password = 'ozapvsxjqlxbbilg' #'149162***'


    # SET THE INFO ABOUT THE SAID EMAIL

    sent_from = gmail_user
    sent_to = ['adapa.usharaman@gmail.com','msubhash535@gmail.com']   # ['msubhash535@gmail.com', 'sm@ttu.edu']
    sent_subject = "Alert! : Intrusion has been detected."
   
    sent_body = ("Hi Network Admin!\n\n"
                 "Intrusion type detected : "+Intrusion_Type+"\n"
                 "Kindly take appropriate action on it.\n"
                 "\n"
                 "\n-----------------------\n"
                 "Regards,\n"
                 "IDS System\n")

   
    message = 'Subject: {}\n\n{}'.format(sent_subject, sent_body)
    # SEND MAIL
    try:
        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.ehlo()
        server.login(gmail_user, gmail_app_password)
        #server.sendmail(sent_from, sent_to, email_text)
        server.sendmail(sent_from, sent_to, message)
        server.close()

        print('Email sent!')
    except Exception as exception:
        print("Error: %s!\n\n" % exception)


#Method call send email

#

 # input data
data_headers=['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
                'root_shell', 'su_attempted', 'num_file_creations', 'num_shells', 'num_access_files', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'rerror_rate',
                'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                'dst_host_srv_diff_host_rate']
data=[0,2,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,16,15,0.94,0,0.94,0.12,0,15,16,0,0.07,0.12]



f = open('C:\\Users\\msubh\\OneDrive\\Desktop\\Project-IICS\\ip.csv', 'w')
row=data
writer = csv.writer(f)
writer.writerow(data_headers)
writer.writerow(row)
f.close()

#
'''
#-------------Pyshark Part

import pyshark

def get_packet_details(packet):
    """
    This function is designed to parse specific details from an individual packet.
    :param packet: raw packet from either a pcap file or via live capture using TShark
    :return: specific packet details
    """
    protocol = packet.transport_layer
    source_address = packet.ip.src
    source_port = packet[packet.transport_layer].srcport
    destination_address = packet.ip.dst
    destination_port = packet[packet.transport_layer].dstport
    packet_time = packet.sniff_time

    # input data
    data_headers=['duration', 'protocol_type', 'flag', 'src_bytes', 'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in', 'num_compromised',
                  'root_shell', 'su_attempted', 'num_file_creations', 'num_shells', 'num_access_files', 'is_guest_login', 'count', 'srv_count', 'serror_rate', 'rerror_rate',
                  'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
                  'dst_host_srv_diff_host_rate']
    data=[0,2,0,42,42,0,0,0,0,0,0,0,0,0,0,0,0,0,16,15,0.94,0,0.94,0.12,0,15,16,0,0.07,0.12]
    f = open('C:\\Users\\msubh\\OneDrive\\Desktop\\Project-IICS\\ip.csv', 'w')
    row=data
    writer = csv.writer(f)
    writer.writerow(row)
    f.close()
    #
    
    return f'Packet Timestamp: {packet_time}' \
           f'\nProtocol type: {protocol}' \
           f'\nSource address: {source_address}' \
           f'\nSource port: {source_port}' \
           f'\nDestination address: {destination_address}' \
           f'\nDestination port: {destination_port}\n'


capture = pyshark.LiveCapture(bpf_filter='udp')     #(bpf_filter='tcp port 80')
capture.sniff(packet_count=10)
#print(capture)
for packet in capture:
    #print(packet.highest_layer)
    print(get_packet_details(packet))

#-------------Pyshark Part end
'''

#-------------Dataset Part
with open("C:\\Users\\msubh\\Downloads\\training_attack_types.txt",'r') as f:
    print(f.read())



    
cols="""duration,
protocol_type,
service,
flag,
src_bytes,
dst_bytes,
land,
wrong_fragment,
urgent,
hot,
num_failed_logins,
logged_in,
num_compromised,
root_shell,
su_attempted,
num_root,
num_file_creations,
num_shells,
num_access_files,
num_outbound_cmds,
is_host_login,
is_guest_login,
count,
srv_count,
serror_rate,
srv_serror_rate,
rerror_rate,
srv_rerror_rate,
same_srv_rate,
diff_srv_rate,
srv_diff_host_rate,
dst_host_count,
dst_host_srv_count,
dst_host_same_srv_rate,
dst_host_diff_srv_rate,
dst_host_same_src_port_rate,
dst_host_srv_diff_host_rate,
dst_host_serror_rate,
dst_host_srv_serror_rate,
dst_host_rerror_rate,
dst_host_srv_rerror_rate"""

columns=[]
for c in cols.split(','):
    if(c.strip()):
        columns.append(c.strip())

columns.append('target')
print(len(columns))


attacks_types = {
    'normal': 'normal',
'back': 'dos',
'buffer_overflow': 'u2r',
'ftp_write': 'r2l',
'guess_passwd': 'r2l',
'imap': 'r2l',
'ipsweep': 'probe',
'land': 'dos',
'loadmodule': 'u2r',
'multihop': 'r2l',
'neptune': 'dos',
'nmap': 'probe',
'perl': 'u2r',
'phf': 'r2l',
'pod': 'dos',
'portsweep': 'probe',
'rootkit': 'u2r',
'satan': 'probe',
'smurf': 'dos',
'spy': 'r2l',
'teardrop': 'dos',
'warezclient': 'r2l',
'warezmaster': 'r2l',
}



datasetpath = "C:\\Users\\msubh\\Downloads\\kddcup.data_10_percent_corrected"
df = pd.read_csv(datasetpath,names=columns)
df['typeofattack'] = df.target.apply(lambda r:attacks_types[r[:-1]])
df.head()


df['target'].value_counts()


df['typeofattack'].value_counts()

df = df.dropna('columns')
df = df[[col for col in df if df[col].nunique() > 1]]# keep columns where there are more than 1 unique values
correl = df.corr()
plt.figure(figsize=(16,14))
sns.heatmap(correl)
plt.show()
plt.close()


df.drop('num_root',axis = 1,inplace = True)
df.drop('srv_serror_rate',axis = 1,inplace = True)
df.drop('srv_rerror_rate',axis = 1, inplace=True)
df.drop('dst_host_srv_serror_rate',axis = 1, inplace=True)
df.drop('dst_host_serror_rate',axis = 1, inplace=True)
df.drop('dst_host_rerror_rate',axis = 1, inplace=True)
df.drop('dst_host_srv_rerror_rate',axis = 1, inplace=True)
df.drop('dst_host_same_srv_rate',axis = 1, inplace=True)
df.drop('service',axis=1,inplace=True)
df.head()


df['protocol_type'].value_counts()



protocolmap = {'icmp':0,'tcp':1,'udp':2}
df['protocol_type'] = df['protocol_type'].map(protocolmap)



df['flag'].value_counts()


fmap = {'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5 ,'S1':6 ,'S2':7,'RSTOS0':8,'S3':9 ,'OTH':10}
df['flag'] = df['flag'].map(fmap)



from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn import metrics


df = df.drop(['target',], axis=1)
print(df.shape)

# Target variable and train set
Y = df[['typeofattack']]
X = df.drop(['typeofattack',], axis=1)

#sc = MinMaxScaler()
#X = sc.fit_transform(X)

# Split test and train data 
X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.33, random_state=42)
print(X_train.shape, X_test.shape)
print(Y_train.shape, Y_test.shape)





from sklearn.feature_selection import RFE
from sklearn.ensemble import RandomForestClassifier
rfc = RandomForestClassifier()
rfe = RFE(rfc, n_features_to_select=30)#30
rfe = rfe.fit(X_train, Y_train.values.ravel())





Y_test_pred = rfe.predict(X_test)
print (Y_test_pred)





print("Train score is:", rfe.score(X_train, Y_train))
print("Test score is:",rfe.score(X_test,Y_test))


print(X_test)

headers=list(X_test.columns)
print(headers)


'''
print("Enter the following")
datalist=[]
for i in headers:
    if(i=="protocol_type"):
        print("Enter icmp:0,tcp:1,udp:2")
        ele=float(input(i))
        datalist.append(ele)
              
    elif(i=="flag"):
        print("Enter 'SF':0,'S0':1,'REJ':2,'RSTR':3,'RSTO':4,'SH':5 ,'S1':6 ,'S2':7,'RSTOS0':8,'S3':9 ,'OTH':10")
        ele=float(input(i))
        datalist.append(ele)
              
    else:
        ele=float(input(i))
        datalist.append(ele)
print(datalist)




import csv
with open("C:\\Users\\msubh\\Downloads\\inputdata.csv", 'w', encoding='UTF8') as f:
    writer = csv.writer(f)
    writer.writerow(headers)
    writer.writerow(datalist)
    f.close()

'''


testingdatapath="C:\\Users\\msubh\\OneDrive\\Desktop\\Project-IICS\\ip.csv"
td=pd.read_csv(testingdatapath)
td.dropna()
td.head()

    

givendatapredict=rfe.predict(td)
print(givendatapredict[0])

if(givendatapredict[0]!='normal'):
    print("Intrusion of type -",givendatapredict[0]," is detected!")
    Send_EMail_Method(givendatapredict[0]+" Attack")
    

#print("--end--")
#----------Dataset Part end


