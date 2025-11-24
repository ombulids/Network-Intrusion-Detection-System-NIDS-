import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report

# 1. Define the column names (The NSL-KDD dataset has 43 columns)
columns = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins',
    'logged_in', 'num_compromised', 'root_shell', 'su_attempted', 'num_root',
    'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
    'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
    'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
    'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate', 'attack', 'level'
]

# 2. Load the dataset
# header=None tells pandas "There is no header in the file"
# names=columns tells pandas "Use these specific names for the columns"
df = pd.read_csv("KDDTrain+.txt", header=None, names=columns)

# 3. Check the structure
print("Shape of dataset:", df.shape)
label_encoder = LabelEncoder()
print(label_encoder)
df['attack'] = label_encoder.fit_transform(df['attack'])
df['protocol_type'] = label_encoder.fit_transform(df['protocol_type'])
df['service'] = label_encoder.fit_transform(df['service'])
df['flag'] = label_encoder.fit_transform(df['flag'])
X = df.iloc[:,0:41]
y = df['attack']
print(y)
Xtrain , Xtest, ytrain , ytest = train_test_split(X,y,random_state=11,test_size=0.2)
rf = RandomForestClassifier()
rf.fit(Xtrain,ytrain)
y_pred = rf.predict(Xtest)
print(rf.score(Xtest,ytest))
print(classification_report(ytest,y_pred))

