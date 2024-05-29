# Disclaimer
$disclaimer = "THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, 
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. 
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES 
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

USE AT YOUR OWN RISK.
"
Write-Host "`n$disclaimer`n" -ForegroundColor Yellow
$confirmation = Read-Host "I accept these conditions and the risk. Proceed? [y/NO]"
while(@("y", "yes") -notcontains $confirmation.ToLower()){
    if (@("n", "no") -contains $confirmation.ToLower()) {
        throw "Aborted. Conditions of use rejected."
    }
    $confirmation = Read-Host "I accept these conditions and the risk. Proceed? [y/NO]"
}

If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) {
    throw "Missing Administrator Privileges. Please run powershell as Administrator."
}