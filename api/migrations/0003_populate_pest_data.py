"""
One-time data migration to populate pest database
Place in: backend/api/migrations/0002_populate_pest_data.py

This will automatically run when you deploy to Render
"""

from django.db import migrations


def load_pest_data(apps, schema_editor):
    """Load 9 actual pest data into database"""
    PestInfo = apps.get_model('api', 'PestInfo')
    
    pests_data = [
        # ========== RICE PESTS (6) ==========
        {
            "name": "Brown Planthopper",
            "scientific_name": "Nilaparvata lugens",
            "crop_affected": "rice",
            "description": "Small brown insect that feeds on rice sap, causing hopper burn and transmitting diseases. One of the most destructive rice pests in tropical Asia.",
            "symptoms": "Yellowing and wilting of leaves starting from the base, stunted growth, hopper burn appearance (brownish patches on leaves), plants become dried and die in circular patches, presence of small brown insects at plant base.",
            "control_methods": "• Use resistant rice varieties (IR varieties)\n• Apply systemic insecticides (imidacloprid, buprofezin, dinotefuran)\n• Maintain proper water management (alternate wetting and drying)\n• Introduce natural predators like spiders and mirid bugs\n• Apply neem-based products for organic control",
            "prevention": "• Monitor fields regularly especially during tillering and flowering stages\n• Avoid excessive nitrogen fertilizer which attracts planthoppers\n• Maintain balanced ecosystem with natural predators\n• Use light traps for monitoring adult populations\n• Practice synchronous planting in the area",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/brown-planthopper.jpg",
            "is_published": True
        },
        {
            "name": "Green Leafhopper",
            "scientific_name": "Nephotettix virescens",
            "crop_affected": "rice",
            "description": "Small green hopping insect that transmits rice tungro virus disease. Major pest that causes significant yield losses in rice fields.",
            "symptoms": "Stunted growth, yellowing of leaves (chlorosis), orange or yellow discoloration starting from leaf tips, transmitted tungro disease causes severe stunting and reduced tillering, presence of small green hopping insects on leaves.",
            "control_methods": "• Use tungro-resistant rice varieties\n• Apply insecticides (imidacloprid, thiamethoxam) at early stages\n• Remove and destroy tungro-infected plants immediately\n• Use light traps to monitor and control adult populations\n• Apply neem oil for organic control",
            "prevention": "• Plant resistant varieties when available\n• Remove infected stubbles and ratoons after harvest\n• Avoid planting near infected fields\n• Synchronize planting dates in the community\n• Monitor fields weekly especially during early growth stages\n• Maintain field sanitation",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/green-leafhopper.jpg",
            "is_published": True
        },
        {
            "name": "Rice Leaf Folder",
            "scientific_name": "Cnaphalocrocis medinalis",
            "crop_affected": "rice",
            "description": "Moth larvae that fold rice leaves lengthwise and feed inside. Causes significant damage by reducing photosynthetic area.",
            "symptoms": "Leaves rolled and folded lengthwise, white or transparent streaks on leaves, larvae visible inside folded leaves, reduced photosynthesis leading to yield loss, leaves appear tubular or cigar-shaped.",
            "control_methods": "• Apply insecticides when larvae are young (chlorantraniliprole, cartap, fipronil)\n• Use biological control with Trichogramma wasps as egg parasitoids\n• Remove and destroy heavily infested leaves\n• Spray neem-based products\n• Encourage natural predators like spiders and ladybugs",
            "prevention": "• Avoid excessive nitrogen fertilizer application which promotes lush growth attractive to pests\n• Maintain proper plant spacing for air circulation\n• Use light traps to monitor adult moths\n• Encourage natural predators through ecological engineering\n• Time planting to avoid peak populations",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/leaf-folder.jpg",
            "is_published": True
        },
        {
            "name": "Rice Bug",
            "scientific_name": "Leptocorisa oratorius",
            "crop_affected": "rice",
            "description": "Elongated bug that feeds on developing rice grains during flowering and grain filling stages, causing grain damage.",
            "symptoms": "Partially filled or empty grains (chalky grains), discolored spots on grains, presence of elongated bugs on rice panicles during flowering and grain filling, foul odor when bugs are disturbed, reduced grain weight and quality.",
            "control_methods": "• Apply insecticides during flowering to early grain filling stage (malathion, cypermethrin, lambda-cyhalothrin)\n• Hand-pick bugs in small fields during early morning when they are sluggish\n• Use sweep nets to remove bugs\n• Avoid spraying during flowering to protect pollinators",
            "prevention": "• Monitor fields regularly during flowering stage\n• Remove weeds especially grasses which serve as alternate hosts\n• Plant early maturing varieties to avoid peak bug populations\n• Use pheromone traps for monitoring\n• Maintain field sanitation",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/rice-bug.jpg",
            "is_published": True
        },
        {
            "name": "Rice Stem Borer",
            "scientific_name": "Scirpophaga incertulas",
            "crop_affected": "rice",
            "description": "Major pest whose larvae bore into rice stems causing deadhearts in vegetative stage and whiteheads in reproductive stage.",
            "symptoms": "Deadhearts (central leaves dry and turn brown) in vegetative stage, whiteheads (empty panicles that remain upright and white) in reproductive stage, hollow stems with frass inside, presence of white or cream colored moths, entry holes visible on stems.",
            "control_methods": "• Apply granular insecticides (cartap hydrochloride, fipronil, chlorantraniliprole) in plant whorl during early infestation\n• Use light traps to catch adult moths\n• Remove and destroy affected plants (deadhearts and whiteheads)\n• Clip egg masses from leaves\n• Maintain proper water level",
            "prevention": "• Use resistant rice varieties\n• Practice proper timing of planting to avoid peak moth emergence\n• Remove crop stubbles immediately after harvest\n• Plow fields after harvest to expose pupae\n• Maintain field sanitation\n• Avoid excessive nitrogen fertilizer\n• Use pheromone traps for monitoring",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/stem-borer.jpg",
            "is_published": True
        },
        {
            "name": "Whorl Maggot",
            "scientific_name": "Hydrellia philippina",
            "crop_affected": "rice",
            "description": "Small fly whose maggots mine rice leaves causing white streaks. Most damaging in nursery beds and young seedlings.",
            "symptoms": "White to yellowish streaks on young leaves (feeding tunnels), damaged and withered leaf tips, stunted plant growth, wilting of central leaves in severe cases, small flies visible on seedlings, greatest damage in nursery beds.",
            "control_methods": "• Apply carbofuran granules in nursery beds before sowing\n• Use systemic insecticides at transplanting (imidacloprid, fipronil)\n• Drain nursery beds temporarily to reduce maggot populations\n• Remove and destroy heavily infested seedlings\n• Use neem cake in nursery soil",
            "prevention": "• Use healthy and pest-free seedlings\n• Avoid over-watering in nursery beds which creates favorable conditions\n• Maintain proper seedling age for transplanting (not too young)\n• Monitor nursery beds regularly\n• Practice crop rotation\n• Avoid planting near old rice stubbles",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/whorl-maggot.jpg",
            "is_published": True
        },
        
        # ========== CORN PESTS (3) ==========
        {
            "name": "Fall Armyworm",
            "scientific_name": "Spodoptera frugiperda",
            "crop_affected": "corn",
            "description": "Invasive pest that feeds on corn leaves and whorls. Caterpillars have characteristic inverted Y marking on head. Can cause severe defoliation.",
            "symptoms": "Irregular holes and ragged edges on leaves, window-pane effect on young leaves, sawdust-like frass in whorl and leaf axils, damaged tassels and silk, caterpillars visible in whorl (greenish-brown with stripes), characteristic inverted Y marking on head, severe defoliation in heavy infestations.",
            "control_methods": "• Early morning hand-picking of larvae and egg masses\n• Apply Bt-based biopesticides (Bacillus thuringiensis) for organic control\n• Use chemical insecticides (chlorantraniliprole, emamectin benzoate, spinetoram) for severe infestations\n• Apply neem-based products for early-stage control\n• Use biological control agents like Trichogramma wasps and egg parasitoids\n• Apply wood ash or sand in whorl to kill larvae",
            "prevention": "• Scout fields regularly especially during early growth stages (V3-V8)\n• Use pheromone traps for early detection and monitoring\n• Practice crop rotation with non-host crops\n• Deep plowing after harvest to expose pupae\n• Plant early to avoid peak populations\n• Maintain field sanitation by removing crop residues\n• Intercrop with repellent plants like Desmodium\n• Coordinate with neighboring farmers for area-wide management",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/armyworm.jpg",
            "is_published": True
        },
        {
            "name": "Asian Corn Borer",
            "scientific_name": "Ostrinia furnacalis",
            "crop_affected": "corn",
            "description": "Major corn pest whose larvae bore into stalks, ears, and tassels. Causes broken stalks, lodging, and ear damage.",
            "symptoms": "Entry holes on stalks with sawdust-like frass, broken stalks or lodging, damaged tassels and ears, larvae tunneling inside stalks (cream colored with brown head), wilting and stunting of plants, premature drying of plants, reduced ear formation.",
            "control_methods": "• Apply granular insecticides in whorl during early larval stage (carbofuran, phorate)\n• Spray insecticides targeting larvae before boring (chlorantraniliprole, lambda-cyhalothrin)\n• Hand-pick and destroy egg masses found on leaves\n• Use light traps to catch adult moths\n• Inject insecticides into tunnels",
            "prevention": "• Plant Bt corn varieties when available which are resistant to borers\n• Destroy crop residues immediately after harvest by plowing or burning\n• Practice proper crop rotation with non-host crops\n• Plant early to avoid peak borer populations\n• Remove alternate host plants (grasses) near field\n• Use pheromone traps for monitoring\n• Install light traps before planting",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/asian-corn-borer.jpg",
            "is_published": True
        },
        {
            "name": "Cotton Bollworm",
            "scientific_name": "Helicoverpa armigera",
            "crop_affected": "corn",
            "description": "Also known as corn earworm. Larvae feed on corn ears and kernels. Polyphagous pest affecting multiple crops.",
            "symptoms": "Entry holes on corn ears near silk, damaged kernels inside ears with frass, larvae visible inside ears (cream to brown colored with stripes), silk clipping, mold growth on damaged kernels, partially eaten kernels, larvae can be green, brown, or pink with longitudinal stripes.",
            "control_methods": "• Apply insecticides targeting early larval stages (chlorantraniliprole, indoxacarb, spinosad)\n• Use Bt corn varieties for biological control\n• Hand-pick and destroy infested ears in small fields\n• Apply mineral oil to silk after pollination to prevent entry\n• Use biological control agents like Trichogramma wasps\n• Time spraying during egg hatching and early larval stage",
            "prevention": "• Plant early to avoid peak moth populations\n• Use pheromone traps for monitoring adult moths\n• Practice crop rotation with non-host crops\n• Remove and destroy crop residues after harvest\n• Maintain good field sanitation\n• Plant trap crops around main field\n• Scout fields regularly during silking and grain filling stages\n• Deep plowing after harvest to expose pupae\n• Coordinate with neighboring farmers for area-wide management",
            "image_url": "https://raw.githubusercontent.com/yourusername/pestcheck/main/assets/pests/bollworm.jpg",
            "is_published": True
        },
    ]
    
    # Clear existing data (optional - remove if you want to keep existing data)
    PestInfo.objects.all().delete()
    
    # Create pest records
    for pest_data in pests_data:
        PestInfo.objects.create(**pest_data)


def reverse_migration(apps, schema_editor):
    """Remove pest data if migration is reversed"""
    PestInfo = apps.get_model('api', 'PestInfo')
    PestInfo.objects.all().delete()


class Migration(migrations.Migration):
    dependencies = [
        ('api', '0002_auto_create_admin'),  # Replace with your actual last migration
    ]

    operations = [
        migrations.RunPython(load_pest_data, reverse_migration),
    ]