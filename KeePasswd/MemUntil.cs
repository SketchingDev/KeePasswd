/*
  KeePass Password Safe - The Open-Source Password Manager
  Copyright (C) 2003-2015 Dominik Reichl <dominik.reichl@t-online.de>

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/
namespace KeePasswd
{
    using System;
    using System.Text;

    public class MemUtil
    {
        /// <summary>
        /// Convert 8 bytes to a 64-bit unsigned integer using Little-Endian
        /// encoding.
        /// </summary>
        /// <param name="pb">Input bytes.</param>
        /// <returns>64-bit unsigned integer.</returns>
        public static ulong BytesToUInt64(byte[] pb)
        {
            if (pb == null) throw new ArgumentNullException("pb");
            if (pb.Length != 8) throw new ArgumentException();

            return pb[0] | ((ulong)pb[1] << 8) | ((ulong)pb[2] << 16) |
                   ((ulong)pb[3] << 24) | ((ulong)pb[4] << 32) | ((ulong)pb[5] << 40) |
                   ((ulong)pb[6] << 48) | ((ulong)pb[7] << 56);
        }

        /// <summary>
        /// Convert 2 bytes to a 16-bit unsigned integer using Little-Endian
        /// encoding.
        /// </summary>
        /// <param name="pb">Input bytes. Array must contain at least 2 bytes.</param>
        /// <returns>16-bit unsigned integer.</returns>
        public static ushort BytesToUInt16(byte[] pb)
        {
            if (pb == null) throw new ArgumentNullException("pb");
            if (pb.Length != 2) throw new ArgumentException();

            return (ushort)(pb[0] | (pb[1] << 8));
        }

        /// <summary>
        /// Convert 4 bytes to a 32-bit unsigned integer using Little-Endian
        /// encoding.
        /// </summary>
        /// <param name="pb">Input bytes.</param>
        /// <returns>32-bit unsigned integer.</returns>
        public static uint BytesToUInt32(byte[] pb)
        {
            if (pb == null) throw new ArgumentNullException("pb");
            if (pb.Length != 4) throw new ArgumentException("Input array must contain 4 bytes!");

            return pb[0] | ((uint)pb[1] << 8) | ((uint)pb[2] << 16) | ((uint)pb[3] << 24);
        }

        /// <summary>
        /// Convert a byte array to a hexadecimal string.
        /// </summary>
        /// <param name="pbArray">Input byte array.</param>
        /// <returns>Returns the hexadecimal string representing the byte
        /// array. Returns <c>null</c>, if the input byte array was <c>null</c>. Returns
        /// an empty string, if the input byte array has length 0.</returns>
        public static string ByteArrayToHexString(byte[] pbArray)
        {
            if (pbArray == null) return null;

            int nLen = pbArray.Length;
            if (nLen == 0) return string.Empty;

            StringBuilder sb = new StringBuilder();

            byte bt, btHigh, btLow;
            for (int i = 0; i < nLen; ++i)
            {
                bt = pbArray[i];
                btHigh = bt; btHigh >>= 4;
                btLow = (byte)(bt & 0x0F);

                if (btHigh >= 10) sb.Append((char)('A' + btHigh - 10));
                else sb.Append((char)('0' + btHigh));

                if (btLow >= 10) sb.Append((char)('A' + btLow - 10));
                else sb.Append((char)('0' + btLow));
            }

            return sb.ToString();
        }
    }
}