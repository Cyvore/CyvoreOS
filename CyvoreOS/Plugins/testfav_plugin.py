from checkObject import Check
import favicon
import requests
from PIL import Image
import imagehash
import re
from Utils.CheckImpersonation import checkUrlImper, checkSourceCodeMirrorAndImper, strip_scheme

LEGITLINKS = {"microsoft": r"https://www.microsoft.com/he-il/", "paypal": r"https://www.paypal.com/il/home",
              "dropbox": r"https://www.dropbox.com/", "twitter": "https://developer.twitter.com/en", "facebook": "https://www.facebook.com/",
              "amazon": r"https://www.amazon.com/", "steam": "https://steamcommunity.com/", "netflix":
              "https://www.netflix.com/"}


def reduce(iconloc, size):
    """This function reduces the resolution of a given image to a given res."""
    ph = Image.open(iconloc)
    ph_resized = ph.resize(size, Image.ANTIALIAS)
    ph_resized.save(iconloc, "ico")


def rotate(iconloc):
    """This function opens an image and rotates it by 90 degrees."""
    image = Image.open(iconloc)
    image = image.rotate(90, expand=True)
    image.save(iconloc, "ico")


def actuallydownload(icon):
    icoresponse = requests.get(icon.url, stream=True)

    # This changes scheme in case download was not successful
    if icoresponse.status_code != 200:
        icoresponse = requests.get(icon.url.replace("http", "https"), stream=True)

    # Produce name for file saving later
    iconloc = r"/hi{}.ico".format(icon.url.rsplit('/', 1)[-1])

    # remove chars which are not allowed by windows for filenames
    iconloc = re.sub(r'[?|$|!]', '', iconloc)

    # Download icon and save it
    with open(iconloc, 'wb') as image:
        for chunk in icoresponse.iter_content(1024):
            image.write(chunk)

    # Get dimensions of icon
    phishicon = Image.open(iconloc)
    width, height = phishicon.size
    return iconloc, width, height

def downloadico(url):
    icons = favicon.get(url)
    if len(icons) == 1:
        return actuallydownload(icons[0]), icons
    else:
        for icon in icons:

            # We'll look for the actual tab icon from all pictures in the page
            if icon.format == "ico" and "ico" in icon.url:
                return actuallydownload(icon), icons


def comparehases(susurl, classification):

    ogurl = LEGITLINKS[classification]

    # Download both icons from sus url and legit url
    susize, susicons = downloadico(susurl)
    susiconloc, suswidth, susheight = susize
    ogsize, ogicons = downloadico(ogurl)
    ogiconloc, owidth, oheight = ogsize

    # Checking if both links are the same (the sus url is downloading the icon from the same place as the original)
    for icon in susicons:
        if icon in ogicons:
            return True

    # If one of the images in bigger than the other - reduce its size.
    # This makes for a better comparison of the hashes.
    if owidth * oheight > suswidth * susheight:
        reduce(ogiconloc, (suswidth, susheight))
    elif owidth * oheight < suswidth * susheight:
        reduce(susiconloc, (owidth, oheight))

    # Get average hash of the legit icon
    ohash = imagehash.average_hash(Image.open(ogiconloc))

    # Get average hash of every rotation of the sus icon
    for i in range(4):
        phash = imagehash.average_hash(Image.open(susiconloc))
        rotate(susiconloc)

        # If the absolute value of the diff of the hash is low enough - the icons are the same.
        print(phash - ohash)
        if phash - ohash < 20:

            return True
    return False


def run_check(chk):
    chk.pluginOutput["PluginName"] = []
    for url in chk.getUrls():
        print("OPR check: ", url)
        classification = checkUrlImper(url)
        if classification is None:
            classification = checkSourceCodeMirrorAndImper(url)
        if classification is None:
            print("Could not determine association for phishing. This does not mean that this page is not phishing.")
        else:
            #print("This page is attempting impersonation to {}.".format(classification))
            result = comparehases(url, classification)
            if result:
                print("Phishing detected!!!")
            else:
                print("Carry on")
            #chk.pluginOutput["PluginName"].append(output)


def describe():
    desc = """Description of PluginName in a sentence """
    return desc