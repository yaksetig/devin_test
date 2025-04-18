import './App.css'

function App() {
  const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
  
  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md bg-white rounded-lg shadow-md p-6">
        <h1 className="text-2xl font-bold text-center mb-6">Circom File Analyzer</h1>
        
        {/* Direct form submission to backend API */}
        <form 
          action={`${API_URL}/analyze`} 
          method="post" 
          encType="multipart/form-data"
          target="_blank"
          className="space-y-4"
        >
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
            <p className="text-gray-500 mb-2">Upload a .circom file for analysis</p>
            <input
              type="file"
              name="file"
              accept=".circom"
              className="block w-full text-sm text-gray-500
                file:mr-4 file:py-2 file:px-4
                file:rounded-md file:border-0
                file:text-sm file:font-semibold
                file:bg-blue-50 file:text-blue-700
                hover:file:bg-blue-100"
              required
            />
          </div>
          
          <div className="mt-4">
            <p className="text-sm font-medium text-gray-700 mb-2">Output Format:</p>
            <div className="flex space-x-4">
              <label className="inline-flex items-center">
                <input
                  type="radio"
                  className="form-radio"
                  name="format"
                  value="pdf"
                />
                <span className="ml-2">PDF</span>
              </label>
              <label className="inline-flex items-center">
                <input
                  type="radio"
                  className="form-radio"
                  name="format"
                  value="txt"
                  defaultChecked
                />
                <span className="ml-2">Text (for debugging)</span>
              </label>
            </div>
          </div>
          
          <div className="flex justify-center">
            <button
              type="submit"
              className="bg-green-500 hover:bg-green-600 text-white py-2 px-6 rounded-md"
            >
              Analyze File
            </button>
          </div>
        </form>
        
        <div className="mt-4 text-center text-sm text-gray-500">
          <p>Upload a .circom file to analyze it with circomspect</p>
          <p>The analysis will be returned as a downloadable file</p>
        </div>
      </div>
    </div>
  )
}

export default App
