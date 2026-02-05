# api/utils.py
# Pest to Crop Type Mapping
# This maps pest names to their associated crop types

PEST_CROP_MAPPING = {
    # Rice Pests
    'stem borer': 'rice',
    'stem-borer': 'rice',
    'stemborer': 'rice',
    'scirpophaga incertulas': 'rice',
    
    'whorl maggot': 'rice',
    'whorl-maggot': 'rice',
    'whorlmaggot': 'rice',
    'hydrellia philippina': 'rice',
    
    'leaf folder': 'rice',
    'leaf-folder': 'rice',
    'leaffolder': 'rice',
    'cnaphalocrocis medinalis': 'rice',
    
    'rice bug': 'rice',
    'rice-bug': 'rice',
    'ricebug': 'rice',
    'leptocorisa oratorius': 'rice',
    
    'green leafhopper': 'rice',
    'green-leafhopper': 'rice',
    'greenleafhopper': 'rice',
    'nephotettix virescens': 'rice',
    
    'brown planthopper': 'rice',
    'brown-planthopper': 'rice',
    'brownplanthopper': 'rice',
    'nilaparvata lugens': 'rice',
    
    # Corn Pests
    'armyworm': 'corn',
    'army worm': 'corn',
    'fall armyworm': 'corn',
    'spodoptera frugiperda': 'corn',
    
    'asian corn borer': 'corn',
    'asian-corn-borer': 'corn',
    'asiancornborer': 'corn',
    'corn borer': 'corn',
    'ostrinia furnacalis': 'corn',
}

def get_crop_from_pest(pest_name):
    """
    Determines the crop type based on the detected pest name.
    Returns 'rice' or 'corn' based on pest classification.
    Defaults to 'rice' if pest is unknown.
    
    Args:
        pest_name (str): The name of the detected pest
        
    Returns:
        str: 'rice' or 'corn'
    """
    if not pest_name:
        return 'rice'  # Default to rice
    
    # Normalize the pest name
    normalized_pest = pest_name.lower().strip()
    
    # Check direct mapping
    if normalized_pest in PEST_CROP_MAPPING:
        return PEST_CROP_MAPPING[normalized_pest]
    
    # Check if pest name contains key terms
    rice_keywords = ['rice', 'planthopper', 'leafhopper', 'stem borer', 'whorl maggot', 'leaf folder']
    corn_keywords = ['corn', 'armyworm', 'army worm', 'borer']
    
    for keyword in rice_keywords:
        if keyword in normalized_pest:
            return 'rice'
    
    for keyword in corn_keywords:
        if keyword in normalized_pest:
            return 'corn'
    
    # Default to rice if uncertain
    return 'rice'