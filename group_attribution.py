import numpy as np
import os
import pandas as pd
#from misc_utils import gpu_test
from featgenerator import group_features
from featgenerator.floss_general_feat import FlossFeatures
from itables import init_notebook_mode, show
from featgenerator import util
from importlib import reload
util = reload(util)

import nltk
nltk.download('words')


# Constants
#HASH_FILE = "APT_MALWARE_SAMPLES.csv"
#HASH_FILE = "ADAPT_SAMPLES.csv"
HASH_FILE = "ADAPTDataset.csv"
HASH_FILE_NAME, _ = os.path.splitext(HASH_FILE)

OUTPUT_DIRECTORY = "data_outputs"
if not os.path.exists(OUTPUT_DIRECTORY):
    os.mkdir(OUTPUT_DIRECTORY)
DATA_PATH = os.path.join(OUTPUT_DIRECTORY, HASH_FILE_NAME)
if not os.path.exists(DATA_PATH):
    os.mkdir(DATA_PATH)

EXIF_FEATURES = 'exif_features'
MALCAT_FEATURES = 'malcat_features'
JOINED_DF = 'joined_df'
ADVERSARY_DATASET = 'adversary_dataset' 
MERGED_ADVERSARY_EXPERIMENT_FINAL = 'merged_adversary_experiment_final'
ALL_FEATURES = 'all_features'
FINAL_FEATURES = 'final_features'
FEAT = 'feat'
STRING_EMBEDDING_DF_FEATURES = 'string_embedding_df_features'
COMBINED = 'combined'

# Save a pd.DataFrame to disk
import csv
def save_dataframe(df: pd.DataFrame, name: str):
    # Use parquest for reuse/training as it maintains high fidelity
    parquet_file = os.path.join(DATA_PATH, f"{HASH_FILE_NAME}_{name}.parquet")
    df.to_parquet(parquet_file)
    print(f"DataFrame saved in parquet format as {parquet_file}")

    # Use csv for manual inspection of the data
    csv_file = os.path.join(DATA_PATH, f"{HASH_FILE_NAME}_{name}.csv")
    temp_df = df.copy()
    temp_df.columns = [col.replace('\n', ' ') for col in temp_df.columns]
    temp_df.columns = [col.replace('\r', ' ') for col in temp_df.columns]
    temp_df.to_csv(csv_file, index=False, float_format="%.10f", encoding="utf-8", quoting = csv.QUOTE_ALL, escapechar='\\')
    print(f"DataFrame saved in CSV format as {csv_file}")

# Load a pd.DataFrame to disk
def load_dataframe(name: str) -> pd.DataFrame:
    # Use parquest for reuse/training as it maintains high fidelity
    parquet_file = os.path.join(DATA_PATH, f"{HASH_FILE_NAME}_{name}.parquet")

    if os.path.exists(parquet_file):
        return pd.read_parquet(parquet_file)
    else:
        return None
    
def get_group_features() -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    exif_features= load_dataframe(EXIF_FEATURES)
    malcat_features = load_dataframe(MALCAT_FEATURES)
    joined_df = load_dataframe(JOINED_DF)
    adversary_dataset = load_dataframe(ADVERSARY_DATASET)
    if exif_features is None or malcat_features is None or joined_df is None or adversary_dataset is None:
        exif_features, malcat_features, joined_df, adversary_dataset = group_features.load_and_prepare_datasets()
        save_dataframe(exif_features, EXIF_FEATURES)
        save_dataframe(malcat_features, MALCAT_FEATURES)
        save_dataframe(joined_df, JOINED_DF)
        save_dataframe(adversary_dataset, ADVERSARY_DATASET)
    return exif_features, malcat_features, joined_df, adversary_dataset

def get_merged_adversary_experiment_final() -> pd.DataFrame:
    merged_adversary_experiment_final = load_dataframe(MERGED_ADVERSARY_EXPERIMENT_FINAL)
    if merged_adversary_experiment_final is None:
        _, _, joined_df, adversary_dataset = get_group_features()
        merged_adversary_experiment_final = adversary_dataset[['hash', 'Normalized_Tag']].merge(joined_df, on="hash")
        save_dataframe(merged_adversary_experiment_final, MERGED_ADVERSARY_EXPERIMENT_FINAL)
    return merged_adversary_experiment_final

def get_all_features() -> pd.DataFrame:
    all_features = load_dataframe(ALL_FEATURES)
    if  all_features is None:
        _, _, joined_df, adversary_dataset = get_group_features()
        all_features = joined_df.merge(adversary_dataset, on = "hash")
        save_dataframe(all_features, ALL_FEATURES)
    return all_features

def get_final_features():
    final_features = load_dataframe(FINAL_FEATURES)
    if final_features is None:
        exif_features, malcat_features, joined_df, adversary_dataset = get_group_features()
        final_features = group_features.process_and_merge_features(exif_features, malcat_features, joined_df, adversary_dataset)
        save_dataframe(final_features, FINAL_FEATURES)
    return final_features

def get_feat_data() -> pd.DataFrame:
    feat = load_dataframe(FEAT)
    if feat is None:
        feat = get_final_features().drop(columns=['Normalized_Tag'])
        save_dataframe(feat, FEAT)
    return feat

def get_string_embedding_df_features():
    string_embedding_df_features = load_dataframe(STRING_EMBEDDING_DF_FEATURES)
    if string_embedding_df_features is None:
        _, _, joined_df, _ = get_group_features()        
        string_embedding_processor = group_features.StringEmbeddingProcessor(joined_df=joined_df)
        string_embedding_df_features = string_embedding_processor.process()
        string_embedding_df_features.columns = string_embedding_df_features.columns.astype(str) 
        save_dataframe(string_embedding_df_features, STRING_EMBEDDING_DF_FEATURES)
    return string_embedding_df_features

def get_combined_data() -> pd.DataFrame:
    combined = load_dataframe(COMBINED)
    if combined is None:
        feat_data = get_feat_data().reset_index(drop=True)
        embedding_data = get_string_embedding_df_features().reset_index(drop=True)
        combined = pd.concat([                
            feat_data,
            embedding_data
        ], axis=1)

        # Count NaNs per column
        # if one has less rows we may get some NaNs. Ifthee are in Feat we can zero them out
        '''print(f"Combining feat:{feat_data.shape} with embeddings:{embedding_data.shape}")
        if feat_data.shape[0] < embedding_data.shape[0]:
            print(f"Feat has {embedding_data.shape[0] - feat_data.shape[0]} less rows than embeddings, these will be replaced with zeros")
            nan_counts = combined.isnull().sum()
            nan_counts = nan_counts[nan_counts > 0] # only cols with nans
            print(nan_counts)
            combined = combined.fillna(0)        
        else:
            raise ValueError("String embedding has less rows than feat and no way to easily fix this.")'''

        save_dataframe(combined, "combined")
    return combined 

# Generate the string embeddings based on the floss features. We might not necessarily use this.
#floss_feat = FlossFeatures()

n_clusters= list(np.arange(5, 120, 5))
modelling = util.Modelling()

#metrics = ["manhattan"] #["euclidean","manhattan"] default = euclidean
#linkages= ["average"] #["average","ward"] default = average

# To combine the string embedding with our features from the Group Attribution pipeline
combined_data = get_combined_data()
print(f"Combined data:{combined_data.shape}")

normalized = get_all_features()[['hash', 'Normalized_Tag']]
assert(combined_data.shape[0] == normalized.shape[0])

all_params, best_param, best_truth_matrix = modelling.find_best_agglo(combined_data, n_clusters, normalized, 'Normalized_Tag')

#all_params, best_param, best_truth_matrix = modelling.find_best_agglo(combined_data, n_clusters, normalized, 'Normalized_Tag', metrics=metrics, linkages=linkages)
print("Combined")
print(f"all_params={all_params}")
print(f"best_param={best_param}")
print(f"best_truth_matrix={best_truth_matrix}")

'''
# Results without the string embeddings
feat = get_feat_data()
print(f"{len(feat.columns)} feat columns")
#all_params, best_param, best_truth_matrix = modelling.find_best_agglo(feat, n_clusters, normalized, 'Normalized_Tag', metrics=metrics, linkages=linkages)
print("No string embeddings")
#print(f"all_params={all_params}")
#print(f"best_param={best_param}")
#print(f"best_truth_matrix={best_truth_matrix}")

# Results with just the string embeddings
string_embedding_df_features = get_string_embedding_df_features()
print(f"{len(string_embedding_df_features.columns)} string_embedding_df_features columns")

#all_params, best_param, best_truth_matrix = modelling.find_best_agglo(string_embedding_df_features, n_clusters, normalized, 'Normalized_Tag', metrics=metrics, linkages=linkages)
print("Just string embeddings")
#print(f"all_params={all_params}")
#print(f"best_param={best_param}")
#print(f"best_truth_matrix={best_truth_matrix}")
'''