'''
Created by fufufanatic (20200808)
STIG Priority App (SPA) is a tool that triages DISA STIG CAT II items according to NIST SP 800-53 Rev 4 Priority Levels
NOTE - Remember to always address CAT I items first!!!
'''

import xml.dom.minidom as xp
import sys

# list to hold security controls according to NIST priority ... nist_priority[0] -> p0, nist_priority[1] -> p1, etc.
nist_priority = [ [], [], [], [] ]
# list to hold newly prioritized CAT II items
ckl_priority = [ [], [], [], [] ]

# parses the 4 priority files in the resource folder to populate the nist_priority list
def set_nist_priority():
    
    for index, priority_level in enumerate(nist_priority):
        # parsing thru NIST priority files created from https://nvd.nist.gov/800-53/Rev4/search
        with open(r'resources\NIST 800-53 Rev 4 - Priority ' + f'{index}.txt', 'r') as f:
            security_control = f.readline().strip()
            # while getting actual values and not EOF
            while security_control:            
                priority_level.append(security_control)
                security_control = f.readline().strip()

# takes a CCI as a parameter and returns the corresponding NIST Security Control
def get_nist_control(ckl_cci):
    
    nist_result = ''

    # parsing thru the CCI List document retrieved from https://cyber.mil/stigs/cci/
    mapper = xp.parse(r'resources\U_CCI_List.xml')
    ccis = mapper.getElementsByTagName('cci_item')
    for cci in ccis:
        if cci.getAttribute('id') == ckl_cci:
            refs = cci.getElementsByTagName('reference')
            for ref in refs:
                # returns the true NIST security control (i.e. if AC-1.2 (iii) is found, then AC-1 is returned)
                nist_result = ref.getAttribute('index').split(' ')[0].split('.')[0]
                return nist_result

    # in this case, the CCI is not found and an empty string is returned (this should almost never happen)
    return nist_result

# takes a checklist file as a parameter and populates ckl_priority list according to each CAT IIs priority
def set_ckl_priority(ckl_file):
    
    ckl = xp.parse(ckl_file)
    vulns = ckl.getElementsByTagName('VULN')
    
    for vuln in vulns:

        # severity is always the second vulnerability attribute in a checklist file
        vuln_sev = vuln.getElementsByTagName('ATTRIBUTE_DATA')[1].firstChild.nodeValue

        # we only care about triaging CAT II items
        if vuln_sev == 'medium':
            vuln_id = vuln.getElementsByTagName('ATTRIBUTE_DATA')[0].firstChild.nodeValue
            vuln_title = vuln.getElementsByTagName('ATTRIBUTE_DATA')[5].firstChild.nodeValue
            vuln_cci = vuln.getElementsByTagName('ATTRIBUTE_DATA')[-1].firstChild.nodeValue
            vuln_nist = get_nist_control(vuln_cci)
            if vuln_nist in nist_priority[1]:
                ckl_priority[1].append( (vuln_id, vuln_nist, vuln_title) )
                continue
            elif vuln_nist in nist_priority[2]:
                ckl_priority[2].append( (vuln_id, vuln_nist, vuln_title) )
                continue
            elif vuln_nist in nist_priority[3]:
                ckl_priority[3].append( (vuln_id, vuln_nist, vuln_title) )
                continue
            else:
                ckl_priority[0].append( (vuln_id, vuln_nist, vuln_title) )

# prints a triaged list of CAT II items
def show_ckl_priority():

    print('\n==== The following CAT II Vuln-IDs are NIST priority P1 and should be implemented FIRST ====\n')
    for vuln in ckl_priority[1]:
        print( f'{vuln[0]} ({vuln[1]}) - {vuln[2]}' )

    print('\n==== The following CAT II Vuln-IDs are NIST priority P2 and should be implemented SECOND ====\n')
    for vuln in ckl_priority[2]:
        print( f'{vuln[0]} ({vuln[1]}) - {vuln[2]}' )

    print('\n==== The following CAT II Vuln-IDs are NIST priority P3 and should be implemented THIRD ====\n')
    for vuln in ckl_priority[3]:
        print( f'{vuln[0]} ({vuln[1]}) - {vuln[2]}' )

    print('\n==== The following CAT II Vuln-IDs are not prioritized by NIST ====\n')
    for vuln in ckl_priority[0]:
        print( f'{vuln[0]} ({vuln[1]}) - {vuln[2]}' )

def main():
    set_nist_priority()
    # the checklist file to be triaged is passed in a parameter
    set_ckl_priority( str(sys.argv[1]) )
    show_ckl_priority()

if __name__ == '__main__':
    main()