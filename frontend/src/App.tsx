import { useState, useEffect } from 'react'
import './App.css'

function App() {
  const [file, setFile] = useState<File | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [outputFormat, setOutputFormat] = useState<'pdf' | 'txt'>('pdf')
  useEffect(() => {
    console.log('Component mounted or updated')
  }, [])

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    console.log('File change event triggered', e.target.files)
    const selectedFile = e.target.files?.[0]
    if (selectedFile) {
      console.log('Selected file:', selectedFile.name, selectedFile.size)
      if (!selectedFile.name.endsWith('.circom')) {
        setError('Please upload a .circom file')
        setFile(null)
        return
      }
      
      const newFile = new File([selectedFile], selectedFile.name, {
        type: selectedFile.type,
        lastModified: selectedFile.lastModified
      })
      
      setFile(newFile)
      console.log('File state updated:', newFile.name)
      setError(null)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!file) {
      setError('Please select a file')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';
      const response = await fetch(`${API_URL}/analyze?format=${outputFormat}`, {
        method: 'POST',
        body: formData,
      })

      if (!response.ok) {
        const errorData = await response.json()
        throw new Error(errorData.error || 'Analysis failed')
      }

      const blob = await response.blob()
      
      const url = window.URL.createObjectURL(blob)
      
      const a = document.createElement('a')
      a.href = url
      a.download = `${file.name.replace('.circom', '')}_analysis.pdf`
      document.body.appendChild(a)
      a.click()
      
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      
      setFile(null)
      if (e.target instanceof HTMLFormElement) {
        e.target.reset()
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unknown error occurred')
    } finally {
      setLoading(false)
    }
  }

  console.log('Rendering with file state:', file ? `${file.name} (${file.size} bytes)` : 'null')
  
  return (
    <div className="min-h-screen bg-gray-100 flex flex-col items-center justify-center p-4">
      <div className="w-full max-w-md bg-white rounded-lg shadow-md p-6">
        <h1 className="text-2xl font-bold text-center mb-6">Circom File Analyzer</h1>
        
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center">
            {file ? (
              <div className="text-green-600">
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-gray-500">
                  {(file.size / 1024).toFixed(2)} KB
                </p>
              </div>
            ) : (
              <div>
                <p className="text-gray-500 mb-2">Upload a .circom file for analysis</p>
                <div className="relative">
                  <input
                    type="file"
                    onChange={handleFileChange}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    accept=".circom"
                  />
                  <button
                    type="button"
                    className="bg-blue-500 hover:bg-blue-600 text-white py-2 px-4 rounded-md"
                  >
                    Select File
                  </button>
                </div>
              </div>
            )}
          </div>
          
          <div className="mt-4">
            <p className="text-sm font-medium text-gray-700 mb-2">Output Format:</p>
            <div className="flex space-x-4">
              <label className="inline-flex items-center">
                <input
                  type="radio"
                  className="form-radio"
                  name="outputFormat"
                  value="pdf"
                  checked={outputFormat === 'pdf'}
                  onChange={() => setOutputFormat('pdf')}
                />
                <span className="ml-2">PDF</span>
              </label>
              <label className="inline-flex items-center">
                <input
                  type="radio"
                  className="form-radio"
                  name="outputFormat"
                  value="txt"
                  checked={outputFormat === 'txt'}
                  onChange={() => setOutputFormat('txt')}
                />
                <span className="ml-2">Text (for debugging)</span>
              </label>
            </div>
          </div>
          
          {error && (
            <div className="text-red-500 text-sm p-2 bg-red-50 rounded-md">
              {error}
            </div>
          )}
          
          <div className="flex justify-center">
            <button
              type="submit"
              disabled={!file || loading}
              className={`py-2 px-6 rounded-md ${
                !file || loading
                  ? 'bg-gray-300 cursor-not-allowed'
                  : 'bg-green-500 hover:bg-green-600 text-white'
              }`}
            >
              {loading ? 'Analyzing...' : 'Analyze File'}
            </button>
          </div>
        </form>
        
        {loading && (
          <div className="text-center mt-4">
            <p className="text-gray-600">
              Running circomspect analysis, please wait...
            </p>
          </div>
        )}
      </div>
    </div>
  )
}

export default App
