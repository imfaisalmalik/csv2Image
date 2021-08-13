# -*- coding: utf-8 -*-
"""
Created on Fri Jan 17 12:13:31 2020
@author: Faisal Hussain
@email: faisal.hussain.engr@gmail.com

--- Paper Reference ----

@inproceedings{hussain2020iot,
  title={IoT DoS and DDoS Attack Detection using ResNet},
  author={Hussain, Faisal and Abbas, Syed Ghazanfar and Husnain, Muhammad and Fayyaz, Ubaid U and Shahzad, Farrukh and Shah, Ghalib A},
  booktitle={2020 IEEE 23rd International Multitopic Conference (INMIC)},
  pages={1--6},
  year={2020},
  organization={IEEE}
}

"""
import os
import pandas as pd
import numpy as np
import cv2
from sklearn import preprocessing


path = 'E:\\Faisal\\IDS Datasets\\CIC-DDoS-19\\CSVs\\CSV-01-12\\01-12\\'
#path = 'E:\\Faisal\\IDS Datasets\\CIC-DDoS-19\\CSVs\\CSV-03-11\\03-11-2\\'


listOfFiles = os.listdir(path)
#print(listOfFiles)
count = 0

dstpath = 'D:\\CICDDoS19_Scaled\\'
dstpath2 = dstpath + 'Normal\\' #All normal Images will be saved in this folder
#os.mkdir(dstpath2)

for fname in listOfFiles:
    print(fname+' dataframe')
    #count = count + 1

    #dst = dstpath + fname + 'Imgs\\'
    dstpath3 = dstpath + fname + 'Imgs\\'
    os.mkdir(dstpath3)
      
    print('--- Reading File into DataFrame ---')
    df = pd.read_csv(path + fname)
    
    print('--- Dropping Useless Features')
    df.drop(labels=['Unnamed: 0', 'Flow ID', ' Source IP', ' Source Port', ' Destination IP', ' Destination Port', ' Protocol', 
                    ' Timestamp', 'SimillarHTTP', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags', 'FIN Flag Count', 
					' PSH Flag Count', ' ECE Flag Count', 'Fwd Avg Bytes/Bulk', ' Fwd Avg Packets/Bulk', ' Fwd Avg Bulk Rate', 
					' Bwd Avg Bytes/Bulk', ' Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', ' RST Flag Count', ' Fwd Header Length.1', 
					'Subflow Fwd Packets', ' Subflow Fwd Bytes', ' Subflow Bwd Packets', ' Subflow Bwd Bytes'], axis=1, inplace=True)
    print('df.shape: ', df.shape)
    
    #Replace all values = Infinity with NAN
    df = df.replace('Infinity', np.NaN)
    # drop rows with missing values
    df.dropna(inplace=True)
    print('df.shape After dropping: ', df.shape)
    
    
    print('Separating Normal & Attack Traffic')
    normal = df[df.loc[:, ' Label'] == 'BENIGN']
    attack = df[df.loc[:, ' Label'] != 'BENIGN']

    print('Normalizing the Normal Traffic')
    normal.drop([' Label'], axis=1, inplace=True)
    #print(normal.shape)
    minmax_scale = preprocessing.MinMaxScaler(feature_range=(0, 255))
    normal1 = minmax_scale.fit_transform(normal)
    normal = pd.DataFrame(normal1)
    
    print('Normalizing the Attack Traffic')
    attack.drop([' Label'], axis=1, inplace=True)
    #print(normal.shape)
    minmax_scale = preprocessing.MinMaxScaler(feature_range=(0, 255))
    attack1 = minmax_scale.fit_transform(attack)
    attack = pd.DataFrame(attack1)
    
    print('Checking size of Normal & Attack Traffic')
    r1 = int(len(normal)/180)
    r2 = int(len(attack)/180)

    
    print('--- Generating Normal Images ----')
    for i in range(0,r1):
        p = i * 180
        q = p + 60    
        img = np.zeros([60,60,3])
        img[:,:,0] = normal.iloc[p:q, 0:60].values
        img[:,:,1] = normal.iloc[q:q+60, 0:60].values
        img[:,:,2] = normal.iloc[q+60:q+120, 0:60].values
        
        imgName = dstpath2 + fname + str(i) +'_normal.png'
        cv2.imwrite(imgName, img)    
        print(i)

    print('--- Generating Attack Images ----')
    for i in range(0,r2):
        p = i * 180
        q = p + 60    
        img = np.zeros([60,60,3])
        img[:,:,0] = attack.iloc[p:q, 0:60].values
        img[:,:,1] = attack.iloc[q:q+60, 0:60].values
        img[:,:,2] = attack.iloc[q+60:q+120, 0:60].values
        

        imgName = dstpath3 + fname + str(i) +'_attack.png'
        cv2.imwrite(imgName, img)    
        print(i)
    print('--- done ---')
print('--- All Done ---')